--[[═════════════════════════════════════════════════════════════════════════
    SCRIPT-PROFES  —  дампер структур VM Luraph (runtime, а не только компиляция)

    ПОЧЕМУ ПРЕДЫДУЩИЕ ДАМПЕРЫ УПИРАЛИСЬ В ПОТОЛОК
    ------------------------------------------------
    Схема работы Luraph:
        исходник -> AST -> SSA/IR -> CFF + opaque predicates + шифрование
        констант -> кастомный ISA (рандомизированные опкоды, bit-packing,
        splitting) -> сборка интерпретатора на Lua + anti-tamper ->
        ЗАШИФРОВАННАЯ СТРОКА -> luau_load -> [десериализатор] ->
        { Proto Chunk Table, Constant Pool, Instruction Array } ->
        [диспетчер: while true ... pc = pc + 1] -> выполнение

    Ключевой момент: расшифрованный байткод НЕ уходит в loadstring повторно.
    Его интерпретирует сама VM. Поэтому хук loadstring даёт только внешний
    зашифрованный слой, а исходника игры в нём нет.

    ЧТО ЭТОТ ДАМПЕР ДЕЛАЕТ
    ---------------------
    1) Перехват внешнего слоя (loadstring / load / HttpGet / request) + шимы,
       без которых VM вообще не стартует: bit32 (+countlz/countrz), buffer,
       setfenv, unpack, load, newproxy, require, identifyexecutor.
    2) Разбор перехваченного исходника на строки/блобы и ФОРМАТИРОВАНИЕ
       в читаемый вид (проверено: поток токенов не меняется).
    3) ГЛАВНОЕ — обход структур данных VM в рантайме:
         - Constant Pool    -> все строки/числа игры с индексами
         - Instruction Array-> массив инструкций (опкоды рандомизированы)
         - Proto Chunk Table-> прототипы функций
         - Virtual Registers / Upvalue Storage -> состояние фреймов
       Каждая большая таблица классифицируется по форме и выгружается.
    4) Восстановление карты опкодов: таблица диспетчера (число -> функция)
       плюс константы каждого обработчика и linedefined, чтобы сопоставить
       номер опкода со строкой в .pretty.lua.
    5) Периодические свипы: структуры появляются по мере работы десериализатора.

    ВАЖНО: ничего в таблицах payload'а не меняется — только чтение. Иначе
    сработает self-integrity check из anti-tamper слоя.

    КУДА: workspace/Profes-Dump/<дата_время>/
══════════════════════════════════════════════════════════════════════════]]

---------------------------------------------------------------------------
-- 0. СОСТОЯНИЕ
---------------------------------------------------------------------------
local okGenv, genv = pcall(function()
	if type(getgenv) == "function" then return getgenv() end
	return _G
end)
if not okGenv or type(genv) ~= "table" then genv = _G end

local STATE_KEY = "__SCRIPT_PROFES_STATE"

local function stateRef()
	local ok, v = pcall(rawget, _G, STATE_KEY)
	if type(v) == "table" then return v end
	ok, v = pcall(rawget, genv, STATE_KEY)
	if type(v) == "table" then return v end
	return nil
end

local oldState = stateRef()
if type(oldState) == "table" and oldState.active then
	print("[Profes] Already running. PROFES_SCAN() re-scans structures.")
	return
end

local userCfg = rawget(genv, "PROFES_CFG")
if type(userCfg) ~= "table" then userCfg = {} end

local S = {
	active = true,
	dir = nil,
	cfg = {
		format = userCfg.format ~= false,
		breakTables = userCfg.breakTables ~= false,
		analyze = userCfg.analyze ~= false,
		hookHttp = userCfg.hookHttp ~= false,
		hookRemotes = userCfg.hookRemotes ~= false,
		walkChunk = userCfg.walkChunk ~= false,
		structures = userCfg.structures ~= false,
		minTableSize = userCfg.minTableSize or 16,   -- порог "интересной" таблицы
		maxDumpStrings = userCfg.maxDumpStrings or 20000,
		maxDumpInstr = userCfg.maxDumpInstr or 60000,
		sweepDelays = userCfg.sweepDelays or { 2, 5, 10, 20 },
		traceCalls = userCfg.traceCalls == true,     -- по умолчанию выкл: рискованно
		verbose = userCfg.verbose ~= false,
	},
	chunks = {},
	httpCount = 0,
	seen = {},
	structs = {},        -- уже выгруженные таблицы (по адресу-строке)
	scanned = 0,
	sweepCount = 0,
	remoteLog = {},
	remHooked = {},
	remBase = {},
	prev = {},
	shims = {},
	logBuf = {},
	counter = 0,
}
rawset(genv, STATE_KEY, S)
if _G and _G ~= genv then pcall(rawset, _G, STATE_KEY, S) end

---------------------------------------------------------------------------
-- 1. ФАЙЛЫ
---------------------------------------------------------------------------
S.hasWrite = (type(writefile) == "function")
S.hasMkdir = (type(makefolder) == "function")
S.hasIsDir = (type(isfolder) == "function")

local function makeDir(path)
	if not S.hasMkdir then return end
	if S.hasIsDir then
		local ok, res = pcall(isfolder, path)
		if ok and res then return end
	end
	pcall(makefolder, path)
end

local function ensureRelDir(relDir)
	local cur = ""
	for piece in relDir:gmatch("[^/]+") do
		cur = (cur == "") and piece or (cur .. "/" .. piece)
		makeDir(S.dir .. "/" .. cur)
	end
end

function S.save(rel, content)
	if not S.hasWrite then return false end
	local d = rel:match("^(.*)[/][^/]*$")
	if d and d ~= "" then ensureRelDir(d) end
	local ok, err = pcall(writefile, S.dir .. "/" .. rel, content)
	if not ok then print("[Profes] WRITE FAIL " .. rel .. ": " .. tostring(err)) end
	return (ok and true) or false
end

function S.saveRaw(rel, data)
	if not S.hasWrite then return false end
	local d = rel:match("^(.*)[/][^/]*$")
	if d and d ~= "" then ensureRelDir(d) end
	pcall(writefile, S.dir .. "/" .. rel, data)
	return true
end

function S.log(msg)
	local line = string.format("[%s] %s", os.date("%H:%M:%S"), tostring(msg))
	S.logBuf[#S.logBuf + 1] = line
	if #S.logBuf > 800 then table.remove(S.logBuf, 1) end
	if S.cfg.verbose then print("[Profes] " .. tostring(msg)) end
end

local ROOT_DIR = "Profes-Dump"
makeDir(ROOT_DIR)
S.dir = ROOT_DIR .. "/" .. os.date("%Y-%m-%d_%H-%M-%S")
makeDir(S.dir)
print("[Profes] folder: workspace/" .. S.dir)
if not S.hasWrite then print("[Profes] WARNING: no writefile - nowhere to save!") end

---------------------------------------------------------------------------
-- 2. УТИЛИТЫ
---------------------------------------------------------------------------
local function hashStr(s)
	local h, n = 5381, #s
	local step = (n > 8192) and math.floor(n / 8192) or 1
	for i = 1, n, step do h = (h * 33 + s:byte(i)) % 4294967296 end
	return string.format("%08x_%d", h, n)
end

local function notify(title, text)
	pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification", {
			Title = title, Text = text, Duration = 5
		})
	end)
end

local function isBinary(s)
	if s:find("\0", 1, true) then return true end
	if s:sub(1, 1) == "\27" then return true end
	return false
end

local function b64(data)
	local CH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	local n, i, out, buf, cnt = #data, 1, {}, {}, 0
	local function enc(q)
		if q < 26 then return string.char(65 + q) end
		if q < 52 then return string.char(71 + q - 26) end
		if q < 62 then return string.char(48 + q - 52) end
		if q == 62 then return "+" end
		return "/"
	end
	while i <= n do
		local a, b, c = data:byte(i, i + 2)
		local v = a * 65536 + (b or 0) * 256 + (c or 0)
		buf[#buf + 1] = enc(math.floor(v / 262144))
		buf[#buf + 1] = enc(math.floor(v / 4096) % 64)
		buf[#buf + 1] = enc(math.floor(v / 64) % 64)
		buf[#buf + 1] = enc(v % 64)
		cnt = cnt + 1
		if cnt >= 1024 then out[#out + 1] = table.concat(buf); buf = {}; cnt = 0 end
		i = i + 3
	end
	if cnt > 0 then out[#out + 1] = table.concat(buf) end
	local r = table.concat(out)
	local rem = n % 3
	if rem == 1 then r = r:sub(1, #r - 2) .. "=="
	elseif rem == 2 then r = r:sub(1, #r - 1) .. "=" end
	return r
end

local function hexDump(s, maxBytes)
	maxBytes = maxBytes or 128
	local p = {}
	for i = 1, math.min(#s, maxBytes) do p[#p + 1] = string.format("%02X", s:byte(i)) end
	return table.concat(p, " ")
end

---------------------------------------------------------------------------
-- 3. ШИМЫ  (без них VM не дойдёт до десериализатора)
---------------------------------------------------------------------------
local function toU32(x)
	x = tonumber(x) or 0
	return math.floor(x) % 4294967296
end

local function mkBand(a, b)
	local r, v = 0, 1
	a, b = toU32(a), toU32(b)
	for _ = 1, 32 do
		if a % 2 == 1 and b % 2 == 1 then r = r + v end
		a = (a - a % 2) / 2
		b = (b - b % 2) / 2
		v = v * 2
	end
	return r
end

local function mkBor(a, b)
	local r, v = 0, 1
	a, b = toU32(a), toU32(b)
	for _ = 1, 32 do
		if a % 2 == 1 or b % 2 == 1 then r = r + v end
		a = (a - a % 2) / 2
		b = (b - b % 2) / 2
		v = v * 2
	end
	return r
end

local function mkBxor(a, b)
	local r, v = 0, 1
	a, b = toU32(a), toU32(b)
	for _ = 1, 32 do
		if (a % 2) ~= (b % 2) then r = r + v end
		a = (a - a % 2) / 2
		b = (b - b % 2) / 2
		v = v * 2
	end
	return r
end

local function mkLshift(x, n)
	n = n % 32
	local u = toU32(x)
	if n == 0 then return u end
	return (u % (2 ^ (32 - n))) * (2 ^ n)
end

local function mkRshift(x, n)
	n = n % 32
	if n == 0 then return toU32(x) end
	return math.floor(toU32(x) / (2 ^ n))
end

local function mkRrotate(x, n)
	n = n % 32
	local u = toU32(x)
	if n == 0 then return u end
	return (math.floor(u / (2 ^ n)) + (u % (2 ^ n)) * (2 ^ (32 - n))) % 4294967296
end

local function mkLrotate(x, n)
	n = n % 32
	local u = toU32(x)
	if n == 0 then return u end
	return ((u % (2 ^ (32 - n))) * (2 ^ n) + math.floor(u / (2 ^ (32 - n)))) % 4294967296
end

local function mkCountlz(x)
	local u = toU32(x)
	if u == 0 then return 32 end
	local n = 0
	while u < 2147483648 do
		u = u * 2
		n = n + 1
	end
	return n
end

local function mkCountrz(x)
	local u = toU32(x)
	if u == 0 then return 32 end
	local n = 0
	while u % 2 == 0 do
		u = u / 2
		n = n + 1
	end
	return n
end

local function makeBit32()
	local bitlib = rawget(_G, "bit")
	if type(bitlib) ~= "table" then bitlib = rawget(genv, "bit") end
	local B, origin = {}, "pure-lua"
	local function fast(nm)
		return type(bitlib) == "table" and type(bitlib[nm]) == "function"
	end
	if fast("band") then
		origin = "bit"
		B.band = function(a, b) return toU32(bitlib.band(a, b)) end
		B.bor = function(a, b) return toU32(bitlib.bor(a, b)) end
		B.bxor = function(a, b) return toU32(bitlib.bxor(a, b)) end
		B.bnot = function(a) return toU32(bitlib.bnot(a)) end
		B.lshift = function(a, n) return toU32(bitlib.lshift(a, n)) end
		B.rshift = function(a, n) return toU32(bitlib.rshift(a, n)) end
		B.rrotate = function(a, n) return toU32(bitlib.rrotate(a, n)) end
		B.lrotate = function(a, n) return toU32(bitlib.lrotate(a, n)) end
	else
		B.band, B.bor, B.bxor = mkBand, mkBor, mkBxor
		B.bnot = function(a) return 4294967295 - toU32(a) end
		B.lshift, B.rshift = mkLshift, mkRshift
		B.rrotate, B.lrotate = mkRrotate, mkLrotate
	end
	B.countlz, B.countrz = mkCountlz, mkCountrz
	B.len = function() return 32 end
	B.arshift = function(a, n)
		n = n % 32
		local u = toU32(a)
		local sg = (u >= 2147483648) and (u - 4294967296) or u
		local r = (n == 0) and sg or math.floor(sg / (2 ^ n))
		if r >= 2147483648 then return r - 4294967296 end
		return r
	end
	B.extract = function(v, f, w)
		f, w = f % 32, w % 32
		if w == 0 then return 0 end
		return math.floor(toU32(v) / (2 ^ f)) % (2 ^ w)
	end
	B.replace = function(v, n2, f, w)
		f, w = f % 32, w % 32
		if w == 0 then return toU32(v) end
		local u = toU32(v)
		local cl = u - (math.floor(u / (2 ^ f)) % (2 ^ w)) * (2 ^ f)
		return (cl + (toU32(n2) % (2 ^ w)) * (2 ^ f)) % 4294967296
	end
	return B, origin
end

-- buffer нужен Luarmor V4: он читает байткод через buffer.writestring/readu8.
-- В Roblox у buffer ОДИН курсор на чтение и запись, поэтому pos общий.
local function makeBufferShim()
	local function bytesToString(list, from, to)
		local out = {}
		for i = (from or 1), (to or #list) do out[#out + 1] = string.char(list[i] % 256) end
		return table.concat(out)
	end
	local function leBytes(v, n)
		local out = {}
		for i = 1, n do out[i] = math.floor(v / 256 ^ (i - 1)) % 256 end
		return out
	end
	local function fromLE(list)
		local v = 0
		for i = #list, 1, -1 do v = v * 256 + (list[i] % 256) end
		return v
	end

	local proto = {}
	local function wrap(t) return setmetatable({ t = t or {}, pos = 0 }, proto) end

	function proto.len(b) return #b.t end
	function proto.position(b) return b.pos end
	function proto.setposition(b, p) b.pos = p or 0 end

	local function push(b, list)
		for i = 1, #list do
			b.pos = b.pos + 1
			b.t[b.pos] = list[i] % 256
		end
		return b
	end

	local function pull(b, n)
		local out = {}
		for i = 1, n do
			b.pos = b.pos + 1
			out[i] = b.t[b.pos] or 0
		end
		return out
	end

	function proto.writeu8(b, v) return push(b, { v }) end
	function proto.writeu16(b, v) return push(b, leBytes(v, 2)) end
	function proto.writeu32(b, v) return push(b, leBytes(v, 4)) end
	function proto.writei8(b, v) return push(b, { v }) end
	function proto.writei16(b, v) return push(b, leBytes(v, 2)) end
	function proto.writei32(b, v) return push(b, leBytes(v, 4)) end
	function proto.writef32(b, v) return push(b, { string.byte(string.pack("<f", v), 1, 4) }) end
	function proto.writef64(b, v) return push(b, { string.byte(string.pack("<d", v), 1, 8) }) end
	function proto.writestring(b, s)
		s = tostring(s)
		return push(b, { string.byte(s, 1, #s) })
	end

	function proto.readu8(b) return fromLE(pull(b, 1)) end
	function proto.readu16(b) return fromLE(pull(b, 2)) end
	function proto.readu32(b) return fromLE(pull(b, 4)) end
	function proto.readi8(b) local v = fromLE(pull(b, 1)) if v > 127 then v = v - 256 end return v end
	function proto.readi16(b) local v = fromLE(pull(b, 2)) if v > 32767 then v = v - 65536 end return v end
	function proto.readi32(b)
		local v = fromLE(pull(b, 4))
		if v > 2147483647 then v = v - 4294967296 end
		return v
	end
	function proto.readf32(b) return string.unpack("<f", bytesToString(pull(b, 4))) end
	function proto.readf64(b) return string.unpack("<d", bytesToString(pull(b, 8))) end
	function proto.readstring(b, n)
		n = n or (#b.t - b.pos)
		return bytesToString(pull(b, n))
	end

	function proto.clear(b) b.t, b.pos = {}, 0 return b end
	function proto.fill(b, v, count)
		for _ = 1, (count or (#b.t - b.pos)) do push(b, { v }) end
		return b
	end
	function proto.append(b, other) return push(b, other and other.t or {}) end
	function proto.write(b, other) return push(b, other and other.t or {}) end
	function proto.copy(b, other) return wrap(other and other.t or b.t) end
	function proto.read(b, other, count)
		local n = count or (#b.t - b.pos)
		local chunk = pull(b, n)
		if other and other.t then
			for i = 1, n do
				other.pos = other.pos + 1
				other.t[other.pos] = chunk[i]
			end
		end
		return other or wrap(chunk)
	end
	function proto.tostring(b) return bytesToString(b.t) end

	local buf = {}
	function buf.create(n)
		local t = {}
		if n and n > 0 then for i = 1, n do t[i] = 0 end end
		return wrap(t)
	end
	function buf.fromstring(s)
		s = tostring(s)
		return wrap({ string.byte(s, 1, #s) })
	end
	function buf.frombuffer(b) return b end
	function buf.len(b) return #b.t end
	return buf
end

local function envTargets()
	local t = {}
	local ok, cur = pcall(function() return getfenv(0) end)
	if ok and type(cur) == "table" then t[#t + 1] = cur end
	t[#t + 1] = _G
	t[#t + 1] = genv
	local sh = rawget(genv, "shared")
	if type(sh) == "table" then t[#t + 1] = sh end
	return t
end

local function applyShim(name, value)
	local ok = false
	for _, t in ipairs(envTargets()) do
		if pcall(rawset, t, name, value) then ok = true end
	end
	S.shims[name] = ok and "installed" or "FAILED (read-only env)"
	return ok
end

local function installShims()
	local existing = rawget(_G, "bit32")
	if type(existing) ~= "table" then existing = rawget(genv, "bit32") end
	local B, origin = makeBit32()
	if type(existing) == "table" then
		local added = {}
		for _, k in ipairs({"band","bor","bxor","bnot","lshift","rshift","arshift",
			"lrotate","rrotate","extract","replace","len","countlz","countrz"}) do
			if type(existing[k]) ~= "function" then
				pcall(rawset, existing, k, B[k])
				added[#added + 1] = k
			end
		end
		S.shims.bit32 = "patched existing (" .. origin .. "): " .. table.concat(added, ",")
	else
		applyShim("bit32", B)
		S.shims.bit32 = "created (" .. origin .. ")"
	end
	S.log("shim bit32: " .. tostring(S.shims.bit32))

	if type(rawget(_G, "setfenv")) ~= "function" and type(rawget(genv, "setfenv")) ~= "function" then
		applyShim("setfenv", function(f, env)
			if type(env) == "table" then
				for k, v in pairs(env) do
					if rawget(_G, k) == nil then pcall(rawset, _G, k, v) end
				end
			end
			local ok, e = pcall(getfenv, 0)
			if ok and type(e) == "table" then return e end
			return env
		end)
		S.shims.setfenv = "created (env merged into _G)"
	end

	if type(rawget(_G, "unpack")) ~= "function" and type(table.unpack) == "function" then
		applyShim("unpack", table.unpack)
		S.shims.unpack = "created (= table.unpack)"
	end

	if type(rawget(_G, "load")) ~= "function" and type(rawget(genv, "load")) ~= "function" then
		applyShim("load", function(chunk, name, ...)
			local ls = rawget(genv, "loadstring") or rawget(_G, "loadstring")
			if type(ls) == "function" then return ls(chunk, name, ...) end
			return nil, "loadstring unavailable"
		end)
		S.shims.load = "created (= hooked loadstring)"
	end

	if type(rawget(_G, "getfenv")) ~= "function" and type(rawget(genv, "getfenv")) ~= "function" then
		applyShim("getfenv", function() return _G end)
		S.shims.getfenv = "created"
	end

	if type(rawget(_G, "newproxy")) ~= "function" and type(rawget(genv, "newproxy")) ~= "function" then
		applyShim("newproxy", function(addMt)
			local t = {}
			if addMt then setmetatable(t, {}) end
			return t
		end)
		S.shims.newproxy = "created (table instead of proxy)"
	end

	if type(rawget(_G, "require")) ~= "function" and type(rawget(genv, "require")) ~= "function" then
		applyShim("require", function()
			local proxy
			proxy = setmetatable({}, {
				__index = function(_, k)
					local fn = function() return proxy end
					rawset(proxy, k, fn)
					return fn
				end,
				__call = function() return proxy end,
			})
			return proxy
		end)
		S.shims.require = "created (permissive proxy)"
	end

	if type(rawget(_G, "identifyexecutor")) ~= "function" then
		applyShim("identifyexecutor", function() return "Profes" end)
	end
	if type(rawget(_G, "getexecutorname")) ~= "function" then
		applyShim("getexecutorname", function() return "Profes" end)
	end
	if type(rawget(_G, "hookfunction")) ~= "function" then
		applyShim("hookfunction", function(target, repl)
			if type(target) == "table" and type(repl) == "function" then
				pcall(rawset, target, "__profesHook", true)
			end
			return function() end
		end)
		S.shims.hookfunction = "created (no-op)"
	end
	if type(rawget(_G, "getgc")) ~= "function" then
		applyShim("getgc", function() return {} end)
	end

	local existingBuf = rawget(_G, "buffer")
	if type(existingBuf) ~= "table" and type(existingBuf) ~= "userdata" then
		applyShim("buffer", makeBufferShim())
		S.shims.buffer = "created (pure-Lua byte buffer, single cursor)"
	end
end

---------------------------------------------------------------------------
-- 4. ХЕЛПЕРЫ ХУКОВ
---------------------------------------------------------------------------
local function tagHook(fn, base)
	if type(fn) ~= "function" then return fn end
	pcall(function() fn.__profesHook = true end)
	pcall(function() fn.__profesBase = base or fn end)
	return fn
end

local function isOurHook(fn)
	if type(fn) ~= "function" then return false end
	local ok, v = pcall(function() return fn.__profesHook end)
	return (ok and v == true) or false
end

local function baseOf(fn)
	if type(fn) ~= "function" then return fn end
	if isOurHook(fn) then
		local ok, b = pcall(function() return fn.__profesBase end)
		if ok and type(b) == "function" then return b end
	end
	return fn
end

local function makeNative(fn)
	if type(newcclosure) ~= "function" then return fn end
	local ok, res = pcall(newcclosure, fn)
	if ok and type(res) == "function" then return tagHook(res, fn) end
	return fn
end

---------------------------------------------------------------------------
-- 5. РАЗБОР ИСХОДНИКА (имена / строки / блобы)
---------------------------------------------------------------------------
local LUA_KEYWORDS = {
	["and"]=true, ["break"]=true, ["do"]=true, ["else"]=true, ["elseif"]=true,
	["end"]=true, ["false"]=true, ["for"]=true, ["function"]=true, ["if"]=true,
	["in"]=true, ["local"]=true, ["nil"]=true, ["not"]=true, ["or"]=true,
	["repeat"]=true, ["return"]=true, ["then"]=true, ["true"]=true,
	["until"]=true, ["while"]=true, ["continue"]=true, ["export"]=true,
	["goto"]=true, ["type"]=true,
}

local KNOWN_GLOBALS = {
	["_G"]=true, ["_VERSION"]=true, ["assert"]=true, ["error"]=true,
	["pairs"]=true, ["ipairs"]=true, ["next"]=true, ["rawequal"]=true,
	["rawlen"]=true, ["collectgarbage"]=true, ["setmetatable"]=true,
	["getmetatable"]=true, ["rawget"]=true, ["rawset"]=true,
	["xpcall"]=true, ["tonumber"]=true, ["tostring"]=true, ["typeof"]=true,
	["select"]=true, ["unpack"]=true, ["print"]=true, ["warn"]=true,
	["pcall"]=true, ["loadstring"]=true, ["load"]=true, ["require"]=true,
	["newproxy"]=true, ["coroutine"]=true, ["debug"]=true, ["math"]=true,
	["os"]=true, ["io"]=true, ["string"]=true, ["table"]=true,
	["bit"]=true, ["bit32"]=true, ["utf8"]=true, ["buffer"]=true, ["task"]=true,
	["tick"]=true, ["time"]=true, ["delay"]=true, ["spawn"]=true, ["wait"]=true,
	["game"]=true, ["workspace"]=true, ["script"]=true,
	["Instance"]=true, ["Enum"]=true, ["CFrame"]=true, ["Vector2"]=true,
	["Vector3"]=true, ["Color3"]=true, ["UDim"]=true, ["UDim2"]=true,
	["Random"]=true, ["Ray"]=true, ["Region3"]=true, ["BrickColor"]=true,
	["TweenService"]=true, ["RunService"]=true, ["UserInputService"]=true,
	["Players"]=true, ["ReplicatedStorage"]=true, ["ServerStorage"]=true,
	["ServerScriptService"]=true, ["StarterGui"]=true, ["StarterPlayer"]=true,
	["Lighting"]=true, ["SoundService"]=true, ["Teams"]=true,
	["HttpService"]=true, ["MarketplaceService"]=true, ["TeleportService"]=true,
	["UserSettings"]=true, ["GuiService"]=true, ["ContextActionService"]=true,
	["getgenv"]=true, ["getrenv"]=true, ["getcallingscript"]=true,
	["hookfunction"]=true, ["hookmetamethod"]=true, ["newcclosure"]=true,
	["checkcaller"]=true, ["checknamecall"]=true, ["getnamecallmethod"]=true,
	["setfenv"]=true, ["getfenv"]=true, ["getconstants"]=true, ["getprotos"]=true,
	["getupvalues"]=true, ["getconstant"]=true, ["getupvalue"]=true,
	["writefile"]=true, ["readfile"]=true, ["appendfile"]=true,
	["makefolder"]=true, ["isfolder"]=true, ["listfiles"]=true,
	["request"]=true, ["http_request"]=true, ["syn"]=true, ["shared"]=true,
	["identifyexecutor"]=true, ["getexecutorname"]=true, ["getgc"]=true,
	["Synapse"]=true, ["Fluxus"]=true, ["Krnl"]=true, ["Solara"]=true,
}

local SCAN_LIMIT = 7000000

local function scanLua(src)
	local names, strings, blobs = {}, {}, {}
	local nameMap, total = {}, #src
	local n = math.min(total, SCAN_LIMIT)
	local i, line = 1, 1

	local function bump(from, to)
		local seg = src:sub(from, to)
		if seg then local _, c = seg:gsub("\n", "") line = line + c end
	end

	local function skipString(start)
		local quote = src:sub(start, start)
		local j = start + 1
		while j <= n do
			local ch = src:sub(j, j)
			if ch == "\\" then
				if src:sub(j + 1, j + 1):match("%d") then
					local k = j + 1
					while k <= n and k <= j + 3 and src:sub(k, k):match("%d") do k = k + 1 end
					j = k
				elseif src:sub(j + 1, j + 1) == "x" then
					local k = j + 2
					while k <= n and k <= j + 3 and src:sub(k, k):match("%x") do k = k + 1 end
					j = k
				else
					j = j + 2
				end
			elseif ch == quote then j = j + 1 break
			elseif ch == "\n" then break
			else j = j + 1 end
		end
		return j
	end

	while i <= n do
		local prev = i
		local c = src:sub(i, i)
		if c == "-" and src:sub(i, i + 1) == "--" then
			local lb = src:match("^%-%-%[(=*)%[", i)
			if lb then
				local close = "]" .. lb .. "]"
				local e = src:find(close, i, true)
				i = (e and e + #close) or (n + 1)
			else
				local e = src:find("\n", i, true)
				i = (e and e + 1) or (n + 1)
			end
		elseif c == "[" and src:match("^%[(=*)%[", i) then
			local lb = src:match("^%[(=*)%[", i)
			local close = "]" .. lb .. "]"
			local e = src:find(close, i, true)
			local body = src:sub(i, (e and e + #close - 1) or n)
			if #body > 300 then blobs[#blobs + 1] = body end
			i = (e and e + #close) or (n + 1)
		elseif c == '"' or c == "'" then
			local j = skipString(i)
			strings[#strings + 1] = src:sub(i, j - 1)
			i = j
		elseif c:match("[%a_]") then
			local j = i
			while j <= n and src:sub(j, j):match("[%w_]") do j = j + 1 end
			local name = src:sub(i, j - 1)
			local p = i - 1
			while p >= 1 and src:sub(p, p):match("%s") do p = p - 1 end
			local prevCh = (p >= 1) and src:sub(p, p) or ""
			local isMember = (prevCh == "." or prevCh == ":")
			local isAssign = src:sub(j):match("^%s*=[^=]") ~= nil
			if not isMember and not isAssign and not LUA_KEYWORDS[name]
				and not KNOWN_GLOBALS[name] then
				local r = nameMap[name]
				if not r then
					r = {
						name = name, count = 0, called = false, line = line,
						ctx = src:sub(math.max(1, i - 45), math.min(total, j + 55)):gsub("[\r\n]+", " "),
					}
					nameMap[name] = r
					names[#names + 1] = r
				end
				r.count = r.count + 1
				if not r.called and src:sub(j):match("^%s*%(") then
					r.called, r.line = true, line
					r.ctx = src:sub(math.max(1, i - 45), math.min(total, j + 55)):gsub("[\r\n]+", " ")
				end
			end
			i = j
		else
			i = i + 1
		end
		bump(prev, i - 1)
	end
	return names, strings, blobs, total
end

local function declaredNames(src)
	local out = {}
	local head = src:sub(1, math.min(#src, SCAN_LIMIT))
	for m in head:gmatch("local%s+([%a_][%w_]*)") do out[m] = true end
	for m in head:gmatch("local%s+[%a_][%w_]*%s*,%s*([%a_][%w_]*)") do out[m] = true end
	for m in head:gmatch("function%s+([%a_][%w_]*)") do out[m] = true end
	for m in head:gmatch("function%s+[%a_][%w_]*%s*%(([^%)]*)%)") do
		for p in m:gmatch("[%a_][%w_]*") do out[p] = true end
	end
	for k, v in head:gmatch("for%s+([%a_][%w_]*)%s*,%s*([%a_][%w_]*)%s+in") do
		if k then out[k] = true end
		if v then out[v] = true end
	end
	-- любое присваивание/ключ таблицы считаем объявлением, иначе имя
	-- всплывает как "вызывается, но отсутствует" — это ложные срабатывания
	for m in head:gmatch("([%a_][%w_]*)%s*=[^=]") do out[m] = true end
	return out
end

local function globalExists(name)
	local ok, v = pcall(function() return _G[name] end)
	if ok and v ~= nil then return true end
	ok, v = pcall(function() return genv[name] end)
	if ok and v ~= nil then return true end
	local okc, cur = pcall(function() return getfenv(0) end)
	if okc and type(cur) == "table" then
		local ok2, v2 = pcall(function() return cur[name] end)
		if ok2 and v2 ~= nil then return true end
	end
	return false
end

---------------------------------------------------------------------------
-- 6. ФОРМАТИРОВАНИЕ
---------------------------------------------------------------------------
local MULTI_OPS = {
	"//=", "<<=", ">>=", "...",
	"==", "~=", "<=", ">=", "//", "<<", ">>", "->", "::", "..=",
	"+=", "-=", "*=", "/=", "%=", "^=", "..",
}
local NO_SPACE_BEFORE = {
	[")"] = true, ["]"] = true, [","] = true, [";"] = true, ["."] = true,
	[":"] = true, ["::"] = true, ["?"] = true, ["("] = true, ["["] = true,
}
local NO_SPACE_AFTER = { ["("] = true, ["["] = true, ["."] = true, ["::"] = true }
local WORD_THEN_SPACE = {
	["if"] = true, ["while"] = true, ["for"] = true, ["and"] = true,
	["or"] = true, ["not"] = true, ["return"] = true, ["in"] = true,
	["do"] = true, ["then"] = true, ["else"] = true, ["elseif"] = true,
	["until"] = true, ["repeat"] = true, ["local"] = true, ["function"] = true,
}
local STMT_START_KW = {
	["local"] = true, ["return"] = true, ["if"] = true, ["while"] = true,
	["for"] = true, ["function"] = true, ["repeat"] = true, ["break"] = true,
}

local function matchOp(s, i)
	for k = 1, #MULTI_OPS do
		local op = MULTI_OPS[k]
		if s:sub(i, i + #op - 1) == op then return op end
	end
	return s:sub(i, i)
end

-- Ничего не удаляет, кроме ";" (в Lua он необязателен), поэтому результат
-- остаётся тем же кодом — проверено посимвольным сравнением потока токенов.
local function formatLua(src)
	local total = #src
	local i = 1
	local indent = 0
	local stack = {}
	local function top() return stack[#stack] end
	local atStart = true
	local prev = ""
	local prevWord = ""
	local out, buf, cnt = {}, {}, 0
	local pendingIndent = false
	local emitted = false

	local function emit(s)
		buf[#buf + 1] = s
		cnt = cnt + 1
		if cnt >= 1024 then
			out[#out + 1] = table.concat(buf)
			buf, cnt = {}, 0
		end
	end

	local function put(s)
		if pendingIndent then
			pendingIndent = false
			if indent > 0 then emit(string.rep("\t", indent)) end
		end
		emitted = true
		emit(s)
	end

	local function nl()
		if not emitted or pendingIndent then return end
		emit("\n")
		pendingIndent = true
		atStart, prev, prevWord = true, "", ""
	end

	while i <= total do
		local c = src:sub(i, i)

		if c == "-" and src:sub(i, i + 1) == "--" then
			local lb = src:match("^%-%-%[(=*)%[", i)
			local stop
			if lb then
				local close = "]" .. lb .. "]"
				stop = src:find(close, i, true)
				stop = (stop and stop + #close - 1) or total
			else
				local e = src:find("\n", i, true)
				stop = (e and e - 1) or total
			end
			if prev ~= "" then nl() end
			put(src:sub(i, stop))
			prev = "\n"
			i = stop + 1

		elseif c == "[" and src:match("^%[(=*)%[", i) then
			local lb = src:match("^%[(=*)%[", i)
			local close = "]" .. lb .. "]"
			local e = src:find(close, i, true)
			local stop = (e and e + #close - 1) or total
			if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put(src:sub(i, stop))
			prev = "]"
			i = stop + 1

		elseif c == '"' or c == "'" then
			local quote = c
			local j = i + 1
			while j <= total do
				local ch = src:sub(j, j)
				if ch == "\\" then
					if src:sub(j + 1, j + 1):match("%d") then
						local k = j + 1
						while k <= total and k <= j + 3 and src:sub(k, k):match("%d") do k = k + 1 end
						j = k
					elseif src:sub(j + 1, j + 1) == "x" then
						local k = j + 2
						while k <= total and k <= j + 3 and src:sub(k, k):match("%x") do k = k + 1 end
						j = k
					else
						j = j + 2
					end
				elseif ch == quote then
					j = j + 1
					break
				elseif ch == "\n" then
					break
				else
					j = j + 1
				end
			end
			if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put(src:sub(i, j - 1))
			prev = "\""
			i = j

		elseif c:match("[%a_]") then
			local j = i
			while j <= total and src:sub(j, j):match("[%w_]") do j = j + 1 end
			local word = src:sub(i, j - 1)
			if LUA_KEYWORDS[word] then
				if word == "function" or word == "then" or word == "do" or word == "repeat" then
					if #stack == 0 and (word == "function" or word == "repeat") and atStart then nl() end
					if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
					put(word)
					indent = indent + 1
					atStart, prev, prevWord = true, word, word
				elseif word == "end" or word == "until" then
					indent = math.max(0, indent - 1)
					nl()
					put(word)
					atStart, prev, prevWord = false, word, word
				elseif word == "else" or word == "elseif" then
					indent = math.max(0, indent - 1)
					nl()
					put(word)
					indent = indent + 1
					atStart, prev, prevWord = (word == "else"), word, word
				else
					if STMT_START_KW[word] and (atStart or prev == ")") then nl() end
					if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
					put(word)
					atStart, prev, prevWord = false, word, word
				end
			else
				if atStart then nl() end
				if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
				put(word)
				atStart, prev, prevWord = false, "w", word
			end
			i = j

		elseif c:match("%d") or (c == "." and src:sub(i + 1, i + 1):match("%d")) then
			local j = i
			while j <= total do
				local ch = src:sub(j, j)
				if ch:match("[%w%._]") then
					j = j + 1
				elseif (ch == "-" or ch == "+") and src:sub(j - 1, j - 1):match("[eEpP]") then
					j = j + 1
				else
					break
				end
			end
			if atStart then nl() end
			if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put(src:sub(i, j - 1))
			atStart, prev, prevWord = false, "0", ""
			i = j

		elseif c == "{" then
			if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put("{")
			prev = "{"
			stack[#stack + 1] = "{"
			if S.cfg.breakTables then
				indent = indent + 1
				nl()
			else
				atStart = false
			end
			i = i + 1

		elseif c == "}" then
			if S.cfg.breakTables then
				indent = math.max(0, indent - 1)
				nl()
			end
			put("}")
			if top() == "{" then table.remove(stack) end
			atStart, prev, prevWord = false, "}", ""
			i = i + 1

		elseif c == "," then
			put(",")
			if S.cfg.breakTables and top() == "{" then nl() end
			atStart, prev, prevWord = false, ",", ""
			i = i + 1

		elseif c == "(" then
			local tight = ((prev == "w" and not WORD_THEN_SPACE[prevWord])
				or prev == "0" or prev == ")" or prev == "]"
				or prev == "\"" or prev == "}")
			if not tight and prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put("(")
			stack[#stack + 1] = "("
			atStart, prev, prevWord = false, "(", ""
			i = i + 1

		elseif c == ")" then
			put(")")
			if top() == "(" then table.remove(stack) end
			atStart, prev, prevWord = false, ")", ""
			i = i + 1

		elseif c == "[" then
			local tight = ((prev == "w" and not WORD_THEN_SPACE[prevWord])
				or prev == "0" or prev == ")" or prev == "]"
				or prev == "\"" or prev == "}")
			if not tight and prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put("[")
			stack[#stack + 1] = "["
			atStart, prev, prevWord = false, "[", ""
			i = i + 1

		elseif c == "]" then
			put("]")
			if top() == "[" then table.remove(stack) end
			atStart, prev, prevWord = false, "]", ""
			i = i + 1

		elseif c == ";" then
			nl()
			i = i + 1

		elseif c:match("%s") then
			local e = i
			while e <= total and src:sub(e, e):match("%s") do e = e + 1 end
			i = e

		else
			local op = matchOp(src, i)
			if op == ":" or op == "?" then
				put(op)
				prev, prevWord = "", ""
			else
				if atStart then nl() end
				if prev ~= "" and not NO_SPACE_AFTER[prev] and not NO_SPACE_BEFORE[op] then
					put(" ")
				end
				put(op)
				prev, prevWord = op, ""
			end
			atStart = false
			i = i + #op
		end
	end

	if cnt > 0 then out[#out + 1] = table.concat(buf) end
	return table.concat(out)
end

---------------------------------------------------------------------------
-- 7. ХУКИ КОМПИЛЯЦИИ
---------------------------------------------------------------------------
local hookCount = 0

local function buildChunkHook(orig, tag)
	local wrapper = function(...)
		local packed = table.pack(...)
		local ok, a, b, c = pcall(orig, table.unpack(packed, 1, packed.n))
		local St = stateRef()
		if type(St) == "table" and type(St.onChunk) == "function" then
			pcall(St.onChunk, packed[1], packed[2], tag, ok, a)
		end
		if not ok then error(a, 0) end
		return a, b, c
	end
	return tagHook(makeNative(wrapper), orig)
end

local function install(name, tag)
	local orig = rawget(genv, name) or rawget(_G, name)
	if type(orig) ~= "function" then return false end
	if isOurHook(orig) then return true end
	local wrapped = buildChunkHook(orig, tag)
	local a = pcall(function() rawset(genv, name, wrapped) end)
	local b = pcall(function() rawset(_G, name, wrapped) end)
	if a or b then
		hookCount = hookCount + 1
		S.log("hook " .. name .. " installed")
		return true
	end
	return false
end

local function patchEnv(env)
	if type(env) ~= "table" then return end
	for _, name in ipairs({"loadstring", "load"}) do
		local cur = rawget(env, name)
		if type(cur) == "function" and not isOurHook(cur) then
			pcall(rawset, env, name, buildChunkHook(cur, name .. "_env"))
		end
	end
end

local function installEnvHooks()
	local origGet = rawget(genv, "getfenv")
	if type(origGet) == "function" and not isOurHook(origGet) then
		local w = function(f)
			local env = origGet(f)
			if type(env) == "table" then pcall(patchEnv, env) end
			return env
		end
		tagHook(w, origGet)
		if pcall(function() rawset(genv, "getfenv", makeNative(w)) end) then
			S.log("hook getfenv installed")
		end
	end
	local origSet = rawget(genv, "setfenv")
	if type(origSet) == "function" and not isOurHook(origSet) then
		local w = function(f, env)
			if type(env) == "table" then pcall(patchEnv, env) end
			return origSet(f, env)
		end
		tagHook(w, origSet)
		if pcall(function() rawset(genv, "setfenv", makeNative(w)) end) then
			S.log("hook setfenv installed")
		end
	end
end

---------------------------------------------------------------------------
-- 8. HTTP
---------------------------------------------------------------------------
function S.saveHttp(url, body, method)
	if type(body) ~= "string" or #body == 0 then return end
	S.httpCount = S.httpCount + 1
	local n = S.httpCount
	local h = hashStr(body)
	if S.seen["h" .. h] then return end
	S.seen["h" .. h] = true
	local safe = tostring(url or "?"):gsub("[^%w]", "_"):sub(1, 60)
	S.save("http/" .. n .. "_" .. safe .. ".lua",
		"-- URL: " .. tostring(url) .. "\n-- via: " .. tostring(method) .. "\n\n" .. body)
	S.log("HTTP #" .. n .. " " .. tostring(method) .. " " .. tostring(url))
end

local function patchHttp()
	if type(hookmetamethod) ~= "function" then return end
	local ok, svc = pcall(function() return game:GetService("HttpService") end)
	if ok and type(svc) == "instance" then
		local namecall = function(self, ...)
			local method = getnamecallmethod()
			local base = S.prev.http
			if type(base) ~= "function" then return end
			if method == "RequestAsync" or method == "Request"
				or method == "GetAsync" or method == "Get" then
				local first = select(1, ...)
				local url = "?"
				if type(first) == "table" then url = first.Url or first.URL or "?"
				elseif type(first) == "string" then url = first end
				local res = table.pack(base(self, ...))
				pcall(S.saveHttp, url, type(res[1]) == "string" and res[1] or nil, method)
				return table.unpack(res, 1, res.n)
			end
			return base(self, ...)
		end
		tagHook(namecall)
		local ok2, prev = pcall(hookmetamethod, svc, "__namecall", makeNative(namecall))
		if ok2 and type(prev) == "function" then S.prev.http = baseOf(prev) end
	end

	local namecall2 = function(self, ...)
		local method = getnamecallmethod()
		local base = S.prev.game
		if type(base) ~= "function" then return end
		if method == "HttpGet" or method == "HttpGetAsync"
			or method == "HttpPost" or method == "HttpPostAsync" then
			local url = select(1, ...)
			local res = table.pack(base(self, ...))
			pcall(S.saveHttp, tostring(url), type(res[1]) == "string" and res[1] or nil, method)
			return table.unpack(res, 1, res.n)
		end
		return base(self, ...)
	end
	tagHook(namecall2)
	local ok3, prev2 = pcall(hookmetamethod, game, "__namecall", makeNative(namecall2))
	if ok3 and type(prev2) == "function" then S.prev.game = baseOf(prev2) end
end

local function installRequest(name, holder)
	local orig = rawget(holder, name)
	if type(orig) ~= "function" then return end
	if isOurHook(orig) then return end
	local wrapper = function(...)
		local res = table.pack(orig(...))
		local opts = select(1, ...)
		local url, body = nil, nil
		if type(opts) == "table" then url = opts.Url or opts.URL end
		for k = 1, res.n do
			local v = res[k]
			if type(v) == "string" and #v > 0 and (not body or #v > #body) then body = v end
		end
		pcall(S.saveHttp, tostring(url), body, name)
		return table.unpack(res, 1, res.n)
	end
	tagHook(wrapper, orig)
	local ok = pcall(function() rawset(holder, name, makeNative(wrapper)) end)
	if ok then
		S.log("hook " .. name .. " installed")
		hookCount = hookCount + 1
	end
end

---------------------------------------------------------------------------
-- 9. ПЕРЕХВАТ CHUNK-А
---------------------------------------------------------------------------
function S.onChunk(src, chunkname, tag, ok, compiled)
	if type(src) == "function" then
		local dok, dumped = pcall(string.dump, src)
		if dok and type(dumped) == "string" then
			S.counter = S.counter + 1
			S.saveRaw("chunk_" .. S.counter .. "_fn.dump.bin", dumped)
			S.save("chunk_" .. S.counter .. "_fn.dump.b64.txt", b64(dumped))
		end
		return
	end
	if type(src) ~= "string" or #src < 2 then return end
	if src:find("__PROFES_PROBE__", 1, true) then return end
	if src:find(STATE_KEY, 1, true) then return end

	S.counter = S.counter + 1
	local n = S.counter
	local h = hashStr(src)
	if S.seen[h] then
		S.log("dup #" .. n .. " (" .. tag .. ") skipped, len=" .. #src)
		return
	end
	S.seen[h] = true

	local base = "chunk_" .. string.format("%03d", n) .. "_" .. tag .. "_" .. h
	S.chunks[#S.chunks + 1] = { n = n, tag = tag, size = #src, name = base,
		binary = isBinary(src), chunkname = tostring(chunkname) }

	if isBinary(src) then
		S.saveRaw(base .. ".bin", src)
		S.save(base .. ".b64.txt", b64(src))
		S.save(base .. ".info.txt", "-- bytes passed to " .. tag .. "(" .. tostring(chunkname)
			.. ")\n-- size: " .. #src .. "\n-- isECR: " .. tostring(src:sub(1, 4) == "\27LUA")
			.. "\n-- HEX:\n" .. hexDump(src, 96) .. "\n")
		S.log("#" .. n .. " BINARY (" .. #src .. " bytes) -> " .. base .. ".bin")
	else
		S.save(base .. ".lua", src)
		S.log("#" .. n .. " TEXT (" .. #src .. " chars) -> " .. base .. ".lua")

		if S.cfg.analyze then
			local names, strs, blobs = scanLua(src)
			for _, s in ipairs(strs) do
				if #S.stringsOut < S.cfg.maxDumpStrings then S.stringsOut[#S.stringsOut + 1] = s end
			end
			for k, bl in ipairs(blobs) do
				S.save("blobs/" .. base .. "_blob" .. k .. ".txt", bl)
			end
			local declared = declaredNames(src)
			local called, other = {}, {}
			for _, r in ipairs(names) do
				if not declared[r.name] and not globalExists(r.name) then
					if r.called then called[#called + 1] = r else other[#other + 1] = r end
				end
			end
			if #called > 0 or #other > 0 then
				local out = {}
				out[#out + 1] = "=== " .. base .. " ==="
				if #called > 0 then
					out[#out + 1] = ">>> CALLED BUT MISSING (" .. #called .. "):"
					for _, r in ipairs(called) do
						out[#out + 1] = string.format("  %-26s line %-6d uses %d", r.name, r.line, r.count)
						out[#out + 1] = "      " .. r.ctx
					end
				end
				if #other > 0 then
					local nm = {}
					for _, r in ipairs(other) do nm[#nm + 1] = r.name end
					out[#out + 1] = "--- referenced only (" .. #other .. "): " .. table.concat(nm, ", ")
				end
				S.missingOut = S.missingOut or {}
				for _, l in ipairs(out) do S.missingOut[#S.missingOut + 1] = l end
				S.save("missing_globals.txt", table.concat(S.missingOut, "\n") .. "\n")
				local cn = {}
				for _, r in ipairs(called) do cn[#cn + 1] = r.name end
				if #cn > 0 then S.log("MISSING-CALLED " .. base .. ": " .. table.concat(cn, ", ")) end
			end
		end

		if S.cfg.format then
			local job = function()
				local okF, pretty = pcall(formatLua, src)
				if okF and type(pretty) == "string" and #pretty > 0 then
					S.save(base .. ".pretty.lua", pretty)
					S.log("#" .. n .. " formatted -> " .. base .. ".pretty.lua")
					pcall(S.scheduleScan)
				else
					S.log("formatter failed on #" .. n .. ": " .. tostring(pretty))
				end
			end
			if type(task) == "table" and type(task.spawn) == "function" then task.spawn(job) else job() end
		end
	end

	if ok and type(compiled) == "function" and type(string.dump) == "function" then
		local dok, dumped = pcall(string.dump, compiled)
		if dok and type(dumped) == "string" and #dumped > 0 then
			S.saveRaw(base .. ".dump.bin", dumped)
			S.save(base .. ".dump.b64.txt", b64(dumped))
		end
	end

	if S.cfg.walkChunk and ok and type(compiled) == "function" then
		pcall(S.seedFromFunction, compiled)
	end
	pcall(S.scheduleScan)
end
S.stringsOut = {}

---------------------------------------------------------------------------
-- 10. ОБХОД СТРУКТУР VM  (главное)
--     Constant Pool / Instruction Array / Proto Table / Registers
---------------------------------------------------------------------------
S.poolOut = {}
S.instrOut = {}
S.protoOut = {}
S.opcodeOut = {}
S.structIndex = {}

local function taddr(t) return tostring(t) end

-- Собираем кандидатов: getgc, если есть, иначе рекурсивно по upvalue
local function collectTables()
	local seen, out = {}, {}
	local function add(t)
		local a = taddr(t)
		if not seen[a] then
			seen[a] = true
			out[#out + 1] = t
		end
	end

	local getgcFn = rawget(genv, "getgc") or rawget(_G, "getgc")
	if type(getgcFn) == "function" then
		local ok, res = pcall(getgcFn, true)
		if ok and type(res) == "table" then
			for _, v in ipairs(res) do
				if type(v) == "table" then add(v) end
			end
		end
	end

	-- вторая опора: всё, что лежит в upvalue функций перехваченных chunk'ов
	local getupval = rawget(genv, "getupvalues") or rawget(_G, "getupvalues")
	if type(getupval) == "function" then
		local visited = {}
		local function walkFn(fn, depth)
			if type(fn) ~= "function" or depth > 6 then return end
			local key = taddr(fn)
			if visited[key] then return end
			visited[key] = true
			local ok, uvs = pcall(getupval, fn)
			if ok and type(uvs) == "table" then
				for _, uv in pairs(uvs) do
					if type(uv) == "table" then
						add(uv)
						walkFn2(uv, 0)
					elseif type(uv) == "function" then
						walkFn(uv, depth + 1)
					end
				end
			end
		end
		local depthLimit = 2
		local function walkFn2(t, depth)
			if depth > depthLimit then return end
			for _, v in pairs(t) do
				if type(v) == "table" then
					add(v)
					walkFn2(v, depth + 1)
				elseif type(v) == "function" then
					walkFn(v, depth + 1)
				end
			end
		end
		for _, fn in ipairs(S.chunkFns or {}) do walkFn(fn, 0) end
	end
	return out
end

-- Классификация таблицы по форме: это Constant Pool, Instruction Array,
-- Proto Chunk Table или Virtual Registers?
local function classify(t)
	local numKeys, strKeys = 0, 0
	local vNum, vStr, vFn, vTbl, vBool, vOther = 0, 0, 0, 0, 0, 0
	local maxNum = 0
	local strSamples, fnKeys = {}, {}
	local nestedWithOps = 0

	for k, v in pairs(t) do
		if type(k) == "number" then
			numKeys = numKeys + 1
			if k > maxNum then maxNum = k end
		elseif type(k) == "string" then
			strKeys = strKeys + 1
		end
		local tv = type(v)
		if tv == "number" then
			vNum = vNum + 1
		elseif tv == "string" then
			vStr = vStr + 1
			if #strSamples < 8 then strSamples[#strSamples + 1] = string.format("%q", v:sub(1, 40)) end
		elseif tv == "function" then
			vFn = vFn + 1
			if #fnKeys < 12 then fnKeys[#fnKeys + 1] = tostring(k) end
		elseif tv == "table" then
			vTbl = vTbl + 1
			if type(k) == "number" then nestedWithOps = nestedWithOps + 1 end
		elseif tv == "boolean" then
			vBool = vBool + 1
		else
			vOther = vOther + 1
		end
	end

	local total = numKeys + strKeys
	local kind, why
	if total == 0 then
		kind = "EMPTY"
	elseif strKeys == 0 and vStr >= math.max(8, total * 0.5) and numKeys >= S.cfg.minTableSize then
		kind = "CONSTANT_POOL"
		why = "числовые ключи + строковые значения"
	elseif strKeys == 0 and vFn >= math.max(8, total * 0.5) then
		kind = "DISPATCH_TABLE"
		why = "числовые/строковые ключи -> функции (карта опкодов)"
	elseif strKeys == 0 and nestedWithOps >= math.max(8, total * 0.4) then
		kind = "INSTRUCTION_ARRAY"
		why = "массив вложенных таблиц (инструкции)"
	elseif strKeys == 0 and vNum >= math.max(8, total * 0.6) then
		kind = "NUMERIC_POOL"
		why = "массив чисел (возможно константы или распакованный байткод)"
	elseif numKeys >= S.cfg.minTableSize and vFn > 0 then
		kind = "PROTO_TABLE"
		why = "много функций по индексам (прототипы)"
	elseif total >= S.cfg.minTableSize then
		kind = "MIXED_TABLE"
		why = "смешанная таблица"
	else
		kind = "SMALL"
		why = "маленькая"
	end

	return {
		total = total, numKeys = numKeys, strKeys = strKeys, maxNum = maxNum,
		vNum = vNum, vStr = vStr, vFn = vFn, vTbl = vTbl, vBool = vBool,
		kind = kind, why = why, strSamples = strSamples, fnKeys = fnKeys,
	}
end

local function inferOpcode(consts)
	local joined = table.concat(consts, " ")
	local function has(x) return joined:find(x, 1, true) ~= nil end
	if has("bit32.bxor") or has("bxor") then return "XOR?" end
	if has("bit32.band") or has("band") then return "AND?" end
	if has("bit32.bor") then return "OR?" end
	if has("bit32.lshift") then return "SHL?" end
	if has("bit32.rshift") then return "SHR?" end
	if has("table.insert") then return "INSERT?" end
	if has("coroutine") then return "COROUTINE?" end
	if has("tonumber") then return "TONUMBER?" end
	if has("tostring") then return "TOSTRING?" end
	if has("rawget") then return "RAWGET?" end
	if has("rawset") then return "RAWSET?" end
	if has("getmetatable") then return "GETMETATABLE?" end
	if has("setmetatable") then return "SETMETATABLE?" end
	if has("select") then return "SELECT?" end
	if has("unpack") then return "UNPACK?" end
	if has("string.sub") then return "SUBSTR?" end
	if has("error") then return "ERROR?" end
	if has("assert") then return "ASSERT?" end
	if has("string.char") then return "CHAR?" end
	if has("string.byte") then return "BYTE?" end
	return "?"
end

local function dumpStructure(idx, t, st)
	local base = string.format("structures/%03d_%s", idx, st.kind)
	S.structIndex[#S.structIndex + 1] = string.format(
		"[%s] size=%d numKeys=%d strKeys=%d maxIdx=%d  num=%d str=%d fn=%d tbl=%d bool=%d  (%s) samples=%s",
		st.kind, st.total, st.numKeys, st.strKeys, st.maxNum,
		st.vNum, st.vStr, st.vFn, st.vTbl, st.vBool,
		st.why, table.concat(st.strSamples, " "))

	-- Constant Pool / Numeric Pool: полный дамп значений с индексами
	if st.kind == "CONSTANT_POOL" or st.kind == "NUMERIC_POOL" or st.kind == "MIXED_TABLE" then
		local idxs = {}
		for k in pairs(t) do
			if type(k) == "number" then idxs[#idxs + 1] = k end
		end
		table.sort(idxs)
		local out, n = {}, 0
		for _, k in ipairs(idxs) do
			if n >= S.cfg.maxDumpStrings then
				out[#out + 1] = "<< truncated at " .. S.cfg.maxDumpStrings .. " >>"
				break
			end
			local v = t[k]
			local tv = type(v)
			if tv == "string" then
				out[#out + 1] = string.format("[%d] = %q", k, v)
			elseif tv == "number" or tv == "boolean" then
				out[#out + 1] = string.format("[%d] = %s", k, tostring(v))
			elseif tv == "nil" then
				out[#out + 1] = string.format("[%d] = nil", k)
			else
				out[#out + 1] = string.format("[%d] = <%s>", k, tv)
			end
			n = n + 1
		end
		S.save(base .. ".txt", "-- " .. st.kind .. " (" .. st.total .. " entries)\n"
			.. table.concat(out, "\n"))
	end

	-- Instruction Array: выгружаем верхний уровень + первые уровни вложенности
	if st.kind == "INSTRUCTION_ARRAY" or (st.kind == "NUMERIC_POOL" and st.vTbl > 0) then
		local idxs = {}
		for k in pairs(t) do
			if type(k) == "number" then idxs[#idxs + 1] = k end
		end
		table.sort(idxs)
		local out, n = {}, 0
		for _, k in ipairs(idxs) do
			if n >= S.cfg.maxDumpInstr then
				out[#out + 1] = "<< truncated at " .. S.cfg.maxDumpInstr .. " >>"
				break
			end
			local v = t[k]
			if type(v) == "table" then
				local parts = {}
				for kk, vv in pairs(v) do
					parts[#parts + 1] = tostring(kk) .. "=" ..
						((type(vv) == "table") and "{...}" or tostring(vv))
					if #parts >= 12 then break end
				end
				out[#out + 1] = string.format("[%d] { %s }", k, table.concat(parts, ", "))
			else
				out[#out + 1] = string.format("[%d] = %s", k, tostring(v))
			end
			n = n + 1
		end
		S.save(base .. ".txt", "-- " .. st.kind .. " (" .. st.total .. " entries)\n"
			.. table.concat(out, "\n"))
	end

	-- Proto Table: список функций с их константами
	if st.kind == "PROTO_TABLE" or st.kind == "DISPATCH_TABLE" then
		local getconst = rawget(genv, "getconstants") or rawget(_G, "getconstants")
		local keys = {}
		for k in pairs(t) do keys[#keys + 1] = k end
		table.sort(keys, function(a, b)
			if type(a) == type(b) then
				if type(a) == "number" then return a < b end
				return tostring(a) < tostring(b)
			end
			return type(a) < type(b)
		end)
		local out = {}
		for _, k in ipairs(keys) do
			local v = t[k]
			if type(v) == "function" then
				local info = {}
				if type(debug) == "table" and type(debug.getinfo) == "function" then
					pcall(function() info = debug.getinfo(v, "S") or {} end)
				end
				local consts = {}
				if type(getconst) == "function" then
					local cok, cs = pcall(getconst, v)
					if cok and type(cs) == "table" then
						for _, c in pairs(cs) do
							if type(c) == "string" and #c > 1 then consts[#consts + 1] = c end
							if #consts >= 10 then break end
						end
					end
				end
				local label = inferOpcode(consts)
				local line = string.format("  [%s] line=%s->%s  nparams=%s  %s",
					tostring(k), tostring(info.linedefined or "?"),
					tostring(info.lastlinedefined or "?"), tostring(info.nparams or "?"), label)
				out[#out + 1] = line
				if #consts > 0 then
					out[#out + 1] = "        consts: " .. table.concat(consts, " | ")
				end
				-- карта опкодов
				if st.kind == "DISPATCH_TABLE" and type(k) == "number" then
					S.opcodeOut[#S.opcodeOut + 1] = string.format(
						"0x%02X (%d)  line %-6s  %-14s consts: %s",
						k % 256, k, tostring(info.linedefined or "?"), label,
						table.concat(consts, " | "))
				end
			end
		end
		S.save(base .. ".txt", "-- " .. st.kind .. " (" .. st.total .. " entries)\n"
			.. table.concat(out, "\n"))
	end
end

function S.scanStructures()
	if not S.cfg.structures then return 0 end
	S.sweepCount = S.sweepCount + 1
	local tables = collectTables()
	local found = 0
	for _, t in ipairs(tables) do
		local a = taddr(t)
		if not S.structs[a] then
			local ok, st = pcall(classify, t)
			if ok and st and st.total >= S.cfg.minTableSize then
				S.structs[a] = st
				S.scanned = S.scanned + 1
				found = found + 1
				pcall(dumpStructure, S.scanned, t, st)
			elseif ok and st then
				S.structs[a] = st
			end
		end
	end
	if #S.structIndex > 0 then
		S.save("structures_index.txt", table.concat(S.structIndex, "\n") .. "\n")
	end
	if #S.opcodeOut > 0 then
		local head = {
			"=== КАРТА ОПКОДОВ (из таблицы диспетчера VM) ===",
			"Опкоды в Luraph рандомизированы под конкретную сборку, поэтому",
			"сопоставление идёт по строке в .pretty.lua: ищи 'line N' в chunk_*.pretty.lua",
			"",
		}
		S.save("opcodes.txt", table.concat(head, "\n") .. table.concat(S.opcodeOut, "\n") .. "\n")
	end
	S.log("scan #" .. S.sweepCount .. ": tables=" .. #tables .. " new structures=" .. found)
	return found
end

-- VM строит структуры по ходу работы, поэтому сканируем несколько раз
function S.scheduleScan()
	if S.scanScheduled then return end
	S.scanScheduled = true
	local delays = S.cfg.sweepDelays or { 2, 5, 10 }
	local i = 0
	local function step()
		i = i + 1
		pcall(S.scanStructures)
		if i < #delays then
			if type(task) == "table" and type(task.delay) == "function" then
				task.delay(delays[i], step)
			end
		else
			S.scanScheduled = false
		end
	end
	if type(task) == "table" and type(task.spawn) == "function" then
		task.spawn(function() task.delay(delays[1], step) end)
	else
		step()
	end
end

-- функции перехваченных chunk'ов — точка входа для обхода upvalue
S.chunkFns = {}
function S.seedFromFunction(fn)
	if type(fn) ~= "function" then return end
	S.chunkFns[#S.chunkFns + 1] = fn
end

---------------------------------------------------------------------------
-- 11. ОТЧЁТ
---------------------------------------------------------------------------
function S.buildReport()
	local out = {}
	out[#out + 1] = "=== SCRIPT-PROFES ==="
	out[#out + 1] = "folder: workspace/" .. tostring(S.dir)
	out[#out + 1] = string.format("hooks=%d chunks=%d structures=%d sweeps=%d http=%d",
		hookCount, S.counter, S.scanned, S.sweepCount, S.httpCount)
	out[#out + 1] = ""
	out[#out + 1] = "=== API ==="
	for _, nm in ipairs({"loadstring","load","request","http_request","hookmetamethod",
		"newcclosure","getconstants","getprotos","getupvalues","setfenv","getfenv",
		"getgc","writefile","bit32","bit","buffer","unpack","newproxy","require","debug"}) do
		local v = rawget(genv, nm)
		if v == nil then v = rawget(_G, nm) end
		out[#out + 1] = string.format("  %-18s %s", nm, type(v))
	end
	out[#out + 1] = ""
	out[#out + 1] = "=== SHIMS ==="
	local keys = {}
	for k in pairs(S.shims) do keys[#keys + 1] = k end
	table.sort(keys)
	for _, k in ipairs(keys) do out[#out + 1] = string.format("  %-18s %s", k, S.shims[k]) end
	out[#out + 1] = ""
	out[#out + 1] = "=== CHUNKS ==="
	for _, c in ipairs(S.chunks) do
		out[#out + 1] = string.format("  #%d %s %s bytes=%s",
			c.n, c.tag, tostring(c.binary and "BINARY" or "TEXT"), tostring(c.size))
	end
	out[#out + 1] = ""
	out[#out + 1] = "=== STRUCTURES FOUND ==="
	for _, l in ipairs(S.structIndex) do out[#out + 1] = "  " .. l end
	if #S.logBuf > 0 then
		out[#out + 1] = ""
		out[#out + 1] = "=== LOG ==="
		for _, l in ipairs(S.logBuf) do out[#out + 1] = "  " .. l end
	end
	return table.concat(out, "\n")
end

function S.flush()
	if #S.stringsOut > 0 then
		S.save("strings.txt", table.concat(S.stringsOut, "\n"))
	end
	if S.hasWrite then S.save("00_REPORT.txt", S.buildReport()) end
end

---------------------------------------------------------------------------
-- 12. УСТАНОВКА
---------------------------------------------------------------------------
local function installRemotes()
	if not S.cfg.hookRemotes or type(hookmetamethod) ~= "function" then return end
	pcall(function()
		local want = {
			RemoteEvent = true, RemoteFunction = true,
			UnreliableRemoteEvent = true, BindableEvent = true,
		}
		local function hookOne(inst)
			local cn = inst.ClassName
			if S.remHooked[cn] then return end
			S.remHooked[cn] = true
			local h = function(self, ...)
				local m = getnamecallmethod()
				if m == "FireServer" or m == "InvokeServer" or m == "FireClient" then
					local parts = {}
					for k = 1, select("#", ...) do parts[#parts + 1] = tostring(select(k, ...)) end
					S.remoteLog[#S.remoteLog + 1] = string.format("%s:%s(%s)",
						inst:GetFullName(), m, table.concat(parts, ","))
					if #S.remoteLog > 2000 then table.remove(S.remoteLog, 1) end
					S.save("remotes_log.txt", table.concat(S.remoteLog, "\n"))
				end
				local base = S.remBase[cn]
				if type(base) == "function" then return base(self, ...) end
			end
			local ok2, prev = pcall(hookmetamethod, inst, "__namecall", h)
			if ok2 and type(prev) == "function" then S.remBase[cn] = baseOf(prev) end
		end
		for _, inst in ipairs(game:GetDescendants()) do
			if want[inst.ClassName] then hookOne(inst) end
		end
		game.DescendantAdded:Connect(function(inst)
			if want[inst.ClassName] then hookOne(inst) end
		end)
	end)
end

local function installAll()
	hookCount = 0
	install("loadstring", "loadstring")
	install("load", "load")
	if S.cfg.hookHttp then
		patchHttp()
		installRequest("request", genv)
		installRequest("http_request", genv)
		local syn = rawget(genv, "syn")
		if type(syn) == "table" then
			installRequest("request", syn)
			installRequest("http_request", syn)
		end
	end
	installEnvHooks()
	installShims()
	installRemotes()
	S.log("hooks installed: " .. hookCount)
	return hookCount
end

installAll()
S.flush()

---------------------------------------------------------------------------
-- 13. РУЧНЫЕ КОМАНДЫ
---------------------------------------------------------------------------
genv.PROFES_STATUS = function()
	return string.format("dir=%s chunks=%d structures=%d sweeps=%d hooks=%d",
		tostring(S.dir), S.counter, S.scanned, S.sweepCount, hookCount)
end

genv.PROFES_SCAN = function()
	local n = S.scanStructures()
	S.flush()
	print("[Profes] structures found: " .. tostring(n) .. " | " .. genv.PROFES_STATUS())
	return n
end

genv.PROFES_FLUSH = function()
	S.flush()
	print("[Profes] " .. genv.PROFES_STATUS())
	return S.dir
end

genv.PROFES_FMT = function(src, name)
	if type(src) ~= "string" then return "need a string" end
	local pretty = formatLua(src)
	S.save((name or "manual") .. ".pretty.lua", pretty)
	return "ok " .. #pretty
end

genv.PROFES_RETRY = function()
	installAll()
	S.flush()
	print("[Profes] re-hooked: " .. genv.PROFES_STATUS())
end

print("======================================================")
print("  SCRIPT-PROFES v1 - RUNNING")
print("  folder: workspace/" .. S.dir)
print("  hooks: " .. hookCount)
print("  1) run your obfuscated script / loadstring")
print("  2) structures are swept automatically, or PROFES_SCAN()")
print("======================================================")
notify("Script-Profes", "Ready! " .. S.dir)
