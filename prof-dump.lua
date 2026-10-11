--[[═════════════════════════════════════════════════════════════════════════
    SCRIPT-PROFES v22 BRUTAL  —  дампер структур VM Luraph + ГЛАВНЫЙ СКРИПТ

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

    ЧТО ЭТОТ ДАМПЕР ДЕЛАЕТ (v2 BRUTAL — новое помечено [NEW])
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
    6) [NEW] ГЛУБОКИЙ ОБХОД ПАМЯТИ: getgc(includeTables) + getrenv +
       рекурсия по upvalue до глубины 8 + обход _G/getgenv/shared/registry.
       Цепляет зашифрованные blob-строки (>512 байт) и вложенные VM-таблицы,
       которые мелкий обход (depth 2) не видел.
    7) [NEW] РЕКОНСТРУКТОР ГЛАВНОГО СКРИПТА: из Constant Pool + Proto Table +
       Instruction Array + closure-дерева собирает ОДИН читаемый файл
       main/FULL_DEOBFUSCATED.lua — максимально близкий к исходнику:
       константы с индексами, функции-прототипы с их константами/upvalue,
       псевдокод инструкций через карту опкодов, живые регистры, все строки.
    8) [NEW] ЖИВОЙ ПЕРЕХВАТ ДИСПЕТЧЕРА: хуки на string.byte/char/sub +
       table.insert/concat/remove фиксируют момент расшифровки констант в
       рантайме и складывают в main/DECRYPTED_CONSTANTS.txt. Это те строки,
       которых НЕТ в статическом пуле — они появляются только при исполнении.
    9) [NEW] ECR/BYTECODE-декодеры: "\27LUA"-контейнеры и EOR-поток
       автоматически расшифровываются в .ecr.lua рядом с бинарником.

    ВАЖНО: ничего в таблицах payload'а не меняется — только чтение. Иначе
    сработает self-integrity check из anti-tamper слоя. Единственное место
    с записью — опциональный traceCalls (по умолчанию ВЫКЛ).

    КУДА: workspace/Profes-Dump/<дата_время>/
        chunk_*.lua / .pretty.lua     — внешний зашифрованный слой (VM)
        structures/                   — сырые структуры VM по видам
        main/FULL_DEOBFUSCATED.lua    — [NEW] ГЛАВНЫЙ СКРИПТ, весь, читаемый
        main/ALL_MAIN_STRINGS.txt     — все строки программы с частотой
        main/DECRYPTED_CONSTANTS.txt  — [NEW] строки, расшифрованные при работе
        main/closure_tree.txt         — дерево прототипов из getprotos
        opcodes.txt                   — карта опкодов диспетчера
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

-- ОРИГИНАЛЬНЫЙ компилятор: берём ДО установки хуков. Через перехваченный
-- load проверять синтаксис нельзя — каждая проверка попала бы в onChunk
-- и засоряла папку фиктивными chunk'ами.
local function pickOrig()
	local a = rawget(genv, "load")
	if type(a) == "function" then return a end
	a = rawget(_G, "load")
	if type(a) == "function" then return a end
	a = rawget(genv, "loadstring")
	if type(a) == "function" then return a end
	a = rawget(_G, "loadstring")
	if type(a) == "function" then return a end
	return nil
end
local ORIG_COMPILER = pickOrig()

local S = {
	active = true,
	dir = nil,
	cfg = {
		format = userCfg.format ~= false,
		breakTables = userCfg.breakTables ~= false,
		analyze = userCfg.analyze ~= false,
		fixSyntax = userCfg.fixSyntax ~= false,   -- проверка + починка синтаксиса
		salvage = userCfg.salvage ~= false,       -- обрезка до целой конструкции
		hookHttp = userCfg.hookHttp ~= false,
		hookRemotes = userCfg.hookRemotes ~= false,
		walkChunk = userCfg.walkChunk ~= false,
		structures = userCfg.structures ~= false,
		mobile = userCfg.mobile ~= false,            -- [MOBILE] режим слабых экзекуторов
		mobilePoll = userCfg.mobilePoll or 1.5,      -- [MOBILE] интервал опроса памяти (сек)
		mobileSweeps = userCfg.mobileSweeps or 40,   -- [MOBILE] сколько опросов держать
		safeHooks = userCfg.safeHooks ~= false,      -- [MOBILE] хуки только через pcall
		minTableSize = userCfg.minTableSize or 16,   -- порог "интересной" таблицы
		maxDumpStrings = userCfg.maxDumpStrings or 20000,
		maxDumpInstr = userCfg.maxDumpInstr or 60000,
		sweepDelays = userCfg.sweepDelays or { 2, 5, 10, 20, 40, 60 },
		traceCalls = userCfg.traceCalls == true,     -- по умолчанию выкл: рискованно
		brutal = userCfg.brutal ~= false,            -- [NEW] глубокий обход + реконструктор
		deepDepth = userCfg.deepDepth or 8,          -- [NEW] глубина рекурсии по upvalue
		blobMin = userCfg.blobMin or 512,            -- [NEW] порог "зашифрованный blob"
		liveDecrypt = userCfg.liveDecrypt ~= false,  -- [NEW] перехват расшифровки констант
		ecr = userCfg.ecr ~= false,                  -- [NEW] авто-расшифровка ECR-контейнеров
		maxDeepTables = userCfg.maxDeepTables or 60000,
		maxFns = userCfg.maxFns or 60000,
		verbose = userCfg.verbose ~= false,
	},
	chunks = {},
	httpCount = 0,
	seen = {},
	structs = {},        -- уже выгруженные таблицы (по адресу-строке)
	scanned = 0,
	sweepCount = 0,
	blobs = {},            -- [NEW] зашифрованные blob-строки из памяти
	decrypted = {},        -- [NEW] константы, пойманные живой расшифровкой
	decryptedSeen = {},
	closureTree = {},      -- [NEW] дерево прототипов getprotos
	ecrInfo = {},           -- [NEW] результаты ECR-декода
	deepCount = 0,
	fnCount = 0,
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

-- АНТИ-СЕБЯ: реестр всех своих таблиц. Любая таблица из этого реестра или
-- содержащая STATE_KEY в ключах/значениях — это МЫ, не добыча. Проверяется
-- в collectTables/collectDeep/harvestLive до классификации.
S.selfTables = {}
local function selfAddr(t)
	local ok, a = pcall(tostring, t)
	if ok and type(a) == "string" then return a end
	return nil
end
local function markSelf(t)
	if type(t) == "table" then
		local a = selfAddr(t)
		if a then S.selfTables[a] = true end
	end
	return t
end
markSelf(S)
markSelf(S.cfg)
markSelf(S.chunks)
markSelf(S.seen)
markSelf(S.structs)
markSelf(S.shims)
markSelf(S.logBuf)
markSelf(S.cap or {})

-- своя ли таблица: по реестру, по маркеру STATE_KEY внутри, по нашим хукам
local function isSelfTable(t)
	if type(t) ~= "table" then return false end
	do
		local a = selfAddr(t)
		if a and S.selfTables[a] then return true end
	end
	-- таблица функций-хуков или состояний: ищем наши метки
	local ok, found = pcall(function()
		for k, v in pairs(t) do
			if k == STATE_KEY then return true end
			if type(k) == "string" and (k == "__profesHook" or k == "__profesBase") then return true end
			if v == S then return true end
			if type(k) == "string" and k:find("__SCRIPT_PROFES_STATE", 1, true) then return true end
			if type(v) == "string" and v:find("__SCRIPT_PROFES_STATE", 1, true) then return true end
		end
		return false
	end)
	return ok and found == true
end

-- своя ли функция: наш хук (метка __profesHook) — не добыча, а инструмент
local function isSelfFn(fn)
	if type(fn) ~= "function" then return false end
	local ok, v = pcall(function() return fn.__profesHook end)
	if ok and v == true then return true end
	-- константы наших функций содержат маркеры дампера
	-- (прямой вызов getconstants: readConstants объявлен ниже по файлу)
	local gc = rawget(genv, "getconstants") or rawget(_G, "getconstants")
	if type(gc) ~= "function" then return false end
	local okc, cs = pcall(gc, fn)
	if not okc or type(cs) ~= "table" then return false end
	if type(cs) == "table" then
		for _, c in pairs(cs) do
			if type(c) == "string" and (c:find("__SCRIPT_PROFES_STATE", 1, true)
				or c:find("FULL_DEOBFUSCATED", 1, true)
				or c:find("brutalScan", 1, true)) then
				return true
			end
		end
	end
	return false
end

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
-- 1.5 MOBILE: детект возможностей экзекутора (iOS/Android урезаны)
--     Проверяем КАЖДУЮ функцию отдельно: на мобиле часто нет getgc,
--     getprotos, getconstants, hookmetamethod, newcclosure. Дампер обязан
--     работать на голом минимуме: loadstring + writefile + debug.
---------------------------------------------------------------------------
S.cap = {}
local function hasFn(holder, name)
	local v = holder and rawget(holder, name)
	return type(v) == "function"
end
local function probeAPI()
	local caps = S.cap
	caps.writefile = type(writefile) == "function"
	caps.makefolder = type(makefolder) == "function"
	caps.getgc = hasFn(genv, "getgc") or hasFn(_G, "getgc")
	caps.getprotos = hasFn(genv, "getprotos") or hasFn(_G, "getprotos")
	caps.getconstants = hasFn(genv, "getconstants") or hasFn(_G, "getconstants")
	caps.getupvalues = hasFn(genv, "getupvalues") or hasFn(_G, "getupvalues")
	caps.getupvalue = hasFn(genv, "getupvalue") or hasFn(_G, "getupvalue")
	caps.getconstant = hasFn(genv, "getconstant") or hasFn(_G, "getconstant")
	caps.hookmetamethod = type(hookmetamethod) == "function"
	caps.newcclosure = type(newcclosure) == "function"
	caps.hookfunction = type(hookfunction) == "function"
	caps.getrenv = type(getrenv) == "function"
	caps.getregistry = type(getregistry) == "function"
	caps.stringdump = type(string.dump) == "function"
	caps.taskspawn = type(task) == "table" and type(task.spawn) == "function"
	caps.taskdelay = type(task) == "table" and type(task.delay) == "function"
	caps.debug_getinfo = type(debug) == "table" and type(debug.getinfo) == "function"
	caps.debug_getupvalue = type(debug) == "table" and type(debug.getupvalue) == "function"
	-- debug.getupvalue — штатный фолбэк, когда нет executor-getupvalues
	caps.canUpvals = caps.getupvalues or caps.debug_getupvalue
	caps.mobile = not (caps.getgc and caps.getprotos and caps.getconstants)
	return caps
end
probeAPI()

-- Единая обёртка чтения upvalue: executor-API -> debug.getupvalue -> пусто.
-- На мобиле чаще всего жив только debug-вариант.
local function readUpvalues(fn)
	local gu = rawget(genv, "getupvalues") or rawget(_G, "getupvalues")
	if type(gu) == "function" then
		local ok, uvs = pcall(gu, fn)
		if ok and type(uvs) == "table" then return uvs end
	end
	if type(debug) == "table" and type(debug.getupvalue) == "function" then
		local out = {}
		local i = 1
		while true do
			local ok, name, val = pcall(debug.getupvalue, fn, i)
			if not ok or name == nil then break end
			out[name or i] = val
			i = i + 1
			if i > 256 then break end
		end
		return out
	end
	return nil
end

-- Единое чтение констант: getconstants -> getconstant по индексу -> пусто.
local function readConstants(fn)
	local gc = rawget(genv, "getconstants") or rawget(_G, "getconstants")
	if type(gc) == "function" then
		local ok, cs = pcall(gc, fn)
		if ok and type(cs) == "table" then return cs end
	end
	local gi = rawget(genv, "getconstant") or rawget(_G, "getconstant")
	if type(gi) == "function" then
		local out = {}
		for i = 1, 512 do
			local ok, v = pcall(gi, fn, i)
			if not ok or v == nil then break end
			out[#out + 1] = v
		end
		if #out > 0 then return out end
	end
	return nil
end

-- Единое чтение проtos: getprotos -> debug.getproto (Solara/others) -> пусто.
local function readProtos(fn)
	local gp = rawget(genv, "getprotos") or rawget(_G, "getprotos")
	if type(gp) == "function" then
		local ok, ps = pcall(gp, fn)
		if ok and type(ps) == "table" then return ps end
	end
	if type(debug) == "table" and type(debug.getproto) == "function" then
		local out = {}
		local i = 1
		while true do
			local ok, p = pcall(debug.getproto, fn, i)
			if not ok or type(p) ~= "function" then break end
			out[#out + 1] = p
			i = i + 1
			if i > 512 then break end
		end
		if #out > 0 then return out end
	end
	return nil
end

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
			-- состояние выставляем ДО nl(): иначе перезапишем его (atStart/prev)
			-- и следующий токен получит лишний пробел
			atStart, prev, prevWord = false, ",", ""
			put(",")
			if S.cfg.breakTables and top() == "{" then nl() end
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
			-- перенос только если дальше есть код: иначе ";" в конце файла
			-- добавлял бы пустую строку при каждом повторном проходе
			local j = i + 1
			while j <= total and src:sub(j, j):match("%s") do j = j + 1 end
			if j <= total then nl() end
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
		binary = isBinary(src), chunkname = tostring(chunkname),
		raw = isBinary(src) and src or nil, ecrBase = base }

	if isBinary(src) then
		S.saveRaw(base .. ".bin", src)
		S.save(base .. ".b64.txt", b64(src))
		S.save(base .. ".info.txt", "-- bytes passed to " .. tag .. "(" .. tostring(chunkname)
			.. ")\n-- size: " .. #src .. "\n-- isECR: " .. tostring(src:sub(1, 4) == "\27LUA")
			.. "\n-- HEX:\n" .. hexDump(src, 96) .. "\n")
		S.log("#" .. n .. " BINARY (" .. #src .. " bytes) -> " .. base .. ".bin")
		-- ECR сразу: мобиле некогда ждать повторного свипа
		pcall(S.tryEcrOnBinary, base, src)
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
					-- форматирование не ломает поток токенов, но исходник мог быть
					-- битым изначально — проверяем и чиним
					if S.cfg.fixSyntax then pcall(S.ensureValid, base, pretty, "pretty") end
					pcall(S.scheduleScan)
				else
					S.log("formatter failed on #" .. n .. ": " .. tostring(pretty))
				end
			end
			if type(task) == "table" and type(task.spawn) == "function" then task.spawn(job) else job() end
		elseif S.cfg.fixSyntax then
			pcall(S.ensureValid, base, src, "raw")
		end

		-- исходник проверяем всегда: даже если форматирование выключено
		if S.cfg.fixSyntax and S.cfg.format then
			pcall(S.ensureValid, base, src, "raw")
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
	local visitedFn = {}

	local function add(t)
		local a = taddr(t)
		if not seen[a] and not isSelfTable(t) then
			seen[a] = true
			out[#out + 1] = t
		end
	end

	-- функции-перехватчики объявляются заранее, иначе walkFn увидит
	-- walkFn2 как nil (upvalue ещё не присвоен) и упадёт
	local walkFn2, walkFn

	-- обход таблиц, встречающихся внутри upvalue
	walkFn2 = function(t, depth)
		if depth > 2 then return end
		local ok, iter = pcall(pairs, t)
		if not ok or type(iter) ~= "function" then return end
		for _, v in pairs(t) do
			if type(v) == "table" then
				add(v)
				walkFn2(v, depth + 1)
			elseif type(v) == "function" then
				walkFn(v, depth + 1)
			end
		end
	end

	-- обход функций: их upvalue + собственные поля (наш хук держит orig в поле)
	walkFn = function(fn, depth)
		if type(fn) ~= "function" or depth > 6 then return end
		if isSelfFn(fn) then return end
		local key = taddr(fn)
		if visitedFn[key] then return end
		visitedFn[key] = true

		do
			local uvs = readUpvalues(fn)
			if type(uvs) == "table" then
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

		-- поля функции: __profesBase указывает на оригинал, если мы обернули
		for _, field in ipairs({"__profesBase", "__profesHook"}) do
			local ok2, v = pcall(function() return fn[field] end)
			if ok2 and type(v) == "table" then
				add(v)
				walkFn2(v, 0)
			end
		end
	end

	local getgcFn = rawget(genv, "getgc") or rawget(_G, "getgc")
	if type(getgcFn) == "function" then
		local ok, res = pcall(getgcFn, true)
		if ok and type(res) == "table" then
			for _, v in ipairs(res) do
				if type(v) == "table" then
					add(v)
					walkFn2(v, 0)
				elseif type(v) == "function" then
					walkFn(v, 0)
				end
			end
		end
	end

	-- наши собственные перехватчики: через них лежит оригинальный loadstring
	for _, name in ipairs({"loadstring", "load"}) do
		local h = rawget(genv, name) or rawget(_G, name)
		if type(h) == "function" then walkFn(h, 0) end
	end

	for _, fn in ipairs(S.chunkFns or {}) do walkFn(fn, 0) end
	for _, fn in ipairs(S.seenFns or {}) do walkFn(fn, 0) end
	return out
end

-- Классификация таблицы по форме: это Constant Pool, Instruction Array,
-- Proto Chunk Table или Virtual Registers?
local function classify(t)
	-- SELF-EXCLUDE: свои таблицы не классифицируем как добычу. Иначе
	-- MULTI_OPS / KEYWORDS / лог-буферы выглядят как CONSTANT_POOL игры.
	if t == S.shims or t == S.cap or t == S.structs or t == S.mainStructs
		or t == S.mainStrings or t == S.decrypted or t == S.closureTree
		or t == S.structIndex or t == S.opcodeOut or t == S.chunks
		or t == S.stringsOut or t == S.blobs then
		return { total = 0, numKeys = 0, strKeys = 0, maxNum = 0,
			vNum = 0, vStr = 0, vFn = 0, vTbl = 0, vBool = 0,
			density = 0, nestedWithOps = 0,
			kind = "SELF", why = "своя таблица дампера", strSamples = {}, fnKeys = {} }
	end
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
	-- доля занятых числовых слотов: плотно (1..N) — список прототипов,
	-- разреженно (31,32,37,80) — карта опкодов
	local density = (maxNum > 0) and (numKeys / maxNum) or 0
	local kind, why

	-- Пороги пропорциональные, а не фиксированные: иначе таблицы меньше
	-- 8 элементов никогда не опознаются (проверено тестом).
	if total == 0 then
		kind = "EMPTY"
		why = "пусто"
	elseif strKeys == 0 and vTbl >= math.max(3, total * 0.4) then
		kind = "INSTRUCTION_ARRAY"
		why = "массив вложенных таблиц (инструкции)"
	elseif strKeys == 0 and vStr >= math.max(3, total * 0.4) then
		kind = "CONSTANT_POOL"
		why = "числовые ключи + строковые значения"
	elseif strKeys == 0 and vFn >= math.max(3, total * 0.5) then
		-- Proto Chunk Table и карта опкодов имеют ОДИНАКОВУЮ форму
		-- (индекс -> функция), поэтому различаем только по плотности ключей
		kind = "FUNC_TABLE"
		why = (density > 0.75)
			and "индексы -> функции, ключи плотные (похоже на Proto Chunk Table)"
			or "индексы -> функции, ключи разреженные (похоже на карту опкодов)"
	elseif strKeys == 0 and vNum >= math.max(3, total * 0.6) then
		kind = "NUMERIC_POOL"
		why = "массив чисел (константы или распакованный байткод)"
	elseif strKeys > 0 and numKeys >= 4 and vFn == 0 and vTbl == 0 then
		kind = "REGISTERS"
		why = "числовые слоты + именованные поля (virtual registers / call stack)"
	elseif total >= S.cfg.minTableSize then
		kind = "MIXED_TABLE"
		why = "смешанная таблица"
	else
		kind = "SMALL"
		why = "маленькая"
	end

	-- SELF-CONTENT: таблица из наших строк (имена функций дампера, шим-строки,
	-- MULTI_OPS) — не добыча. Иначе свой мусор выглядит как CONSTANT_POOL игры.
	if kind == "CONSTANT_POOL" and vStr >= 4 and strKeys == 0 then
		local selfHit = 0
		for _, s in ipairs(strSamples) do
			if s:find("brutalScan", 1, true) or s:find("collectDeep", 1, true)
				or s:find("seedFromFunction", 1, true) or s:find("scanStructures", 1, true)
				or s:find("flushFixes", 1, true) or s:find("scheduleScan", 1, true)
				or s:find("buildClosureTree", 1, true) or s:find("created (", 1, true)
				or s:find("installed", 1, true) then
				selfHit = selfHit + 1
			end
		end
		if selfHit >= 2 then
			kind = "SELF"
			why = "контент дампера (имена функций/логи/шимы)"
		end
	end

	return {
		total = total, numKeys = numKeys, strKeys = strKeys, maxNum = maxNum,
		vNum = vNum, vStr = vStr, vFn = vFn, vTbl = vTbl, vBool = vBool,
		density = density, nestedWithOps = nestedWithOps,
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
	if st.kind == "FUNC_TABLE" then
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
				do
					local cs = readConstants(v)
					if type(cs) == "table" then
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
				if st.kind == "FUNC_TABLE" and type(k) == "number" then
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
			if ok and st and st.kind == "SELF" then
				S.structs[a] = st
			elseif ok and st and st.total >= S.cfg.minTableSize then
				S.structs[a] = st
				S.scanned = S.scanned + 1
				found = found + 1
				pcall(dumpStructure, S.scanned, t, st)
				-- запоминаем структуру для выгрузки MAIN-скрипта
				S.mainStructs[#S.mainStructs + 1] = { t = t, kind = st.kind, stat = st }
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
	-- MAIN-СКРИПТ: Constant Pool / Instruction Array / Proto Table из рантайма
	pcall(S.dumpMain)
	pcall(S.dumpVMState)
	pcall(S.brutalScan)
	S.log("scan #" .. S.sweepCount .. ": tables=" .. #tables .. " new structures=" .. found)
	return found
end

-- MOBILE-ПОЛЛЕР: на слабых экзекуторах task.delay может отсутствовать или
-- VM строит структуры поздно. Крутим опрос N раз с интервалом: каждый проход
-- делает scanStructures + brutalScan + flush. Останавливается сам.
function S.startMobilePoller()
	if S.pollerStarted then return end
	S.pollerStarted = true
	local interval = S.cfg.mobilePoll or 1.5
	local total = S.cfg.mobileSweeps or 40
	S.log(string.format("mobile poller: %d sweeps every %.1fs (caps: getgc=%s protos=%s consts=%s upvals=%s dump=%s)",
		total, interval, tostring(S.cap.getgc), tostring(S.cap.getprotos),
		tostring(S.cap.getconstants), tostring(S.cap.canUpvals), tostring(S.cap.stringdump)))
	local count = 0
	local function one()
		count = count + 1
		pcall(S.scanStructures)
		pcall(S.flushDecrypted)
		pcall(S.flush)
		pcall(S.flushFixes)
		if count < total then
			if type(task) == "table" and type(task.delay) == "function" then
				task.delay(interval, one)
			elseif type(delay) == "function" then
				delay(interval, one)
			elseif type(wait) == "function" then
				pcall(wait, interval)
				one()
			end
		else
			S.log("mobile poller done: " .. count .. " sweeps")
		end
	end
	if type(task) == "table" and type(task.spawn) == "function" then
		task.spawn(function()
			if type(task.delay) == "function" then task.delay(interval, one) else one() end
		end)
	else
		one()
	end
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
S.seenFns = {}
S.seenFnMap = {}
function S.seedFromFunction(fn)
	if type(fn) ~= "function" then return end
	if isSelfFn(fn) then return end
	S.chunkFns[#S.chunkFns + 1] = fn
	local k = tostring(fn)
	if not S.seenFnMap[k] then
		S.seenFnMap[k] = true
		S.seenFns[#S.seenFns + 1] = fn
	end
end

---------------------------------------------------------------------------
-- 10.5 MAIN-СКРИПТ: собираем всё, что VM держит в рантайме
--      Из расшифрованной программы в живом состоянии можно вытащить:
--        - Constant Pool      -> все строки/числа игры (имена методов, URL, GUI)
--        - Instruction Array  -> сами инструкции (опкоды рандомизированы)
--        - Proto Chunk Table  -> список функций программы
--        - живое состояние    -> virtual registers / call stack
--      Плюс перехват вызовов: какие функции и с какими аргументами зовёт игра.
---------------------------------------------------------------------------
S.mainStrings = {}
S.mainStructs = {}
S.callLog = {}
markSelf(S.mainStrings)
markSelf(S.mainStructs)
markSelf(S.callLog)

local function vstr(v, cap)
	v = tostring(v)
	cap = cap or 120
	if #v > cap then return v:sub(1, cap) .. "..." end
	return v
end

-- все строки из всех структур, с частотой (главный интеллектуальный выход)
local function harvestStrings(t, out, depth, cap)
	if depth > 4 or #out > S.cfg.maxDumpStrings then return end
	for _, v in pairs(t) do
		local tv = type(v)
		if tv == "string" then
			if #v > 1 then
				out[#out + 1] = v
			end
		elseif tv == "table" then
			harvestStrings(v, out, depth + 1, cap)
		end
	end
end

local function dumpFreq(entries, path, title)
	if #entries == 0 then return end
	local freq = {}
	for _, s in ipairs(entries) do
		freq[s] = (freq[s] or 0) + 1
	end
	local keys = {}
	for k in pairs(freq) do keys[#keys + 1] = k end
	table.sort(keys, function(a, b)
		local fa, fb = freq[a], freq[b]
		if fa ~= fb then return fa > fb end
		return a < b
	end)
	local out = { "-- " .. title .. " (" .. #keys .. " unique / " .. #entries .. " total)" }
	local n = 0
	for _, k in ipairs(keys) do
		if n >= S.cfg.maxDumpStrings then
			out[#out + 1] = "<< truncated >>"
			break
		end
		out[#out + 1] = string.format("%-6d %q", freq[k], k)
		n = n + 1
	end
	S.save(path, table.concat(out, "\n") .. "\n")
end

-- Constant Pool -> main/const_pool.txt (порядок как в VM, это важно для чтения)
local function dumpConstPool(t, name)
	local idxs = {}
	for k in pairs(t) do
		if type(k) == "number" then idxs[#idxs + 1] = k end
	end
	table.sort(idxs)
	local out = {
		"=== CONSTANT POOL / STRING TABLE [" .. name .. "] ===",
		"Индексы совпадают с теми, что использует GETGLOBAL/SETGLOBAL в VM.",
		"",
	}
	local strs = {}
	for _, k in ipairs(idxs) do
		local v = t[k]
		local tv = type(v)
		if tv == "string" then
			out[#out + 1] = string.format("[%d] = %q", k, v)
			if #v > 1 then strs[#strs + 1] = v end
		elseif tv == "number" or tv == "boolean" then
			out[#out + 1] = string.format("[%d] = %s", k, tostring(v))
		else
			out[#out + 1] = string.format("[%d] = <%s>", k, tv)
		end
	end
	-- строковые ключи, если есть
	local skeys = {}
	for k in pairs(t) do
		if type(k) == "string" then skeys[#skeys + 1] = k end
	end
	if #skeys > 0 then
		table.sort(skeys)
		out[#out + 1] = ""
		out[#out + 1] = "-- string keys:"
		for _, k in ipairs(skeys) do
			local v = t[k]
			if type(v) == "string" then
				out[#out + 1] = string.format("%q = %q", k, v)
				if #v > 1 then strs[#strs + 1] = v end
			else
				out[#out + 1] = string.format("%q = %s", k, vstr(v, 60))
			end
		end
	end
	S.save(name .. "_const_pool.txt", table.concat(out, "\n") .. "\n")
	return strs
end

-- Instruction Array -> main/instructions.txt
local function dumpInstructions(t, name)
	local idxs = {}
	for k in pairs(t) do
		if type(k) == "number" then idxs[#idxs + 1] = k end
	end
	table.sort(idxs)
	local out = {
		"=== INSTRUCTION ARRAY [" .. name .. "] ===",
		"Опкоды рандомизированы под сборку. Сопоставь первый элемент каждой",
		"инструкции с opcodes.txt (там есть обработчик и его строка в VM).",
		"",
	}
	for _, k in ipairs(idxs) do
		if #out >= S.cfg.maxDumpInstr then
			out[#out + 1] = "<< truncated at " .. S.cfg.maxDumpInstr .. " >>"
			break
		end
		local v = t[k]
		if type(v) == "table" then
			local parts = {}
			for kk, vv in pairs(v) do
				parts[#parts + 1] = tostring(kk) .. "=" .. vstr(vv, 40)
				if #parts >= 16 then break end
			end
			out[#out + 1] = string.format("[%d] { %s }", k, table.concat(parts, ", "))
		else
			out[#out + 1] = string.format("[%d] = %s", k, vstr(v, 80))
		end
	end
	S.save(name .. "_instructions.txt", table.concat(out, "\n") .. "\n")
end

-- Proto Chunk Table -> main/protos.txt
local function dumpProtos(t, name)
	local keys = {}
	for k in pairs(t) do keys[#keys + 1] = k end
	table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
	local out = { "=== PROTO CHUNK TABLE [" .. name .. "] (" .. #keys .. ") ===", "" }
	local strs = {}
	for _, k in ipairs(keys) do
		local v = t[k]
		if type(v) == "function" then
			local info = {}
			if type(debug) == "table" and type(debug.getinfo) == "function" then
				pcall(function() info = debug.getinfo(v, "Su") or {} end)
			end
			out[#out + 1] = string.format("[%s]  nparams=%s isvararg=%s",
				tostring(k), tostring(info.nparams or "?"), tostring(info.isvararg or "?"))
			do
				local cs = readConstants(v)
				if type(cs) == "table" then
					local parts = {}
					for _, c in pairs(cs) do
						local tc = type(c)
						if tc == "string" and #c > 1 then
							parts[#parts + 1] = string.format("%q", c:sub(1, 60))
							strs[#strs + 1] = c
						elseif tc == "number" or tc == "boolean" then
							parts[#parts + 1] = tostring(c)
						end
						if #parts >= 40 then break end
					end
					if #parts > 0 then
						out[#out + 1] = "   consts: " .. table.concat(parts, ", ")
					end
				end
			end
			do
				local uvs = readUpvalues(v)
				if type(uvs) == "table" then
					local names = {}
					for kk, uv in pairs(uvs) do
						names[#names + 1] = tostring(kk) .. ":" .. type(uv)
						if #names >= 20 then break end
					end
					if #names > 0 then
						out[#out + 1] = "   upvals: " .. table.concat(names, ", ")
					end
				end
			end
		else
			out[#out + 1] = string.format("[%s] = <%s> %s", tostring(k), type(v), vstr(v, 60))
		end
	end
	S.save(name .. "_protos.txt", table.concat(out, "\n") .. "\n")
	return strs
end

-- Живое состояние: virtual registers / call stack
local function dumpRegisters(t, name)
	local idxs = {}
	for k in pairs(t) do
		if type(k) == "number" then idxs[#idxs + 1] = k end
	end
	table.sort(idxs)
	local out = { "=== LIVE STATE [" .. name .. "] (" .. #idxs .. " numeric slots) ===", "" }
	for _, k in ipairs(idxs) do
		if #out >= 4000 then out[#out + 1] = "<< truncated >>" break end
		local v = t[k]
		local tv = type(v)
		if tv == "string" then
			out[#out + 1] = string.format("R[%d] = %q", k, v:sub(1, 100))
		elseif tv == "table" then
			local parts = {}
			for kk, vv in pairs(v) do
				parts[#parts + 1] = tostring(kk) .. "=" .. vstr(vv, 30)
				if #parts >= 8 then break end
			end
			out[#out + 1] = string.format("R[%d] = { %s }", k, table.concat(parts, ", "))
		else
			out[#out + 1] = string.format("R[%d] = %s", k, vstr(v, 80))
		end
	end
	-- строковые ключи
	local skeys = {}
	for k in pairs(t) do
		if type(k) == "string" then skeys[#skeys + 1] = k end
	end
	if #skeys > 0 then
		table.sort(skeys)
		out[#out + 1] = ""
		out[#out + 1] = "-- named slots:"
		for _, k in ipairs(skeys) do
			out[#out + 1] = string.format("%s = %s", k, vstr(t[k], 80))
		end
	end
	S.save(name .. "_state.txt", table.concat(out, "\n") .. "\n")
end

-- Перехват вызовов функций программы: показывает, что игра реально делает.
-- Включается только при PROFES_CFG.traceCalls = true (identity-mетки VM
-- могут сломаться, поэтому по умолчанию выключено).
function S.installCallTracer(protos, name)
	if not S.cfg.traceCalls then return end
	local log = {}
	for key, fn in pairs(protos) do
		if type(fn) == "function" then
			local real = fn
			pcall(rawset, protos, key, function(...)
				local parts = {}
				for i = 1, select("#", ...) do
					parts[#parts + 1] = vstr((select(i, ...)), 40)
					if #parts >= 8 then break end
				end
				if #log < 5000 then
					log[#log + 1] = string.format("%s(%s)", tostring(key), table.concat(parts, ", "))
				end
				return real(...)
			end)
		end
	end
	if #log > 0 then
		S.save(name .. "_calls.txt", table.concat(log, "\n") .. "\n")
	end
end

-- Собираем main из всех структур сразу
function S.dumpMain()
	if not S.cfg.structures then return 0 end
	local found = 0
	for idx, rec in ipairs(S.mainStructs) do
		local t = rec.t
		if t then
			found = found + 1
			local base = string.format("main/%03d_%s", idx, rec.kind)
			if rec.kind == "CONSTANT_POOL" then
				local strs = dumpConstPool(t, base)
				for _, s in ipairs(strs) do S.mainStrings[#S.mainStrings + 1] = s end
			elseif rec.kind == "INSTRUCTION_ARRAY" then
				dumpInstructions(t, base)
				harvestStrings(t, S.mainStrings, 1)
			elseif rec.kind == "FUNC_TABLE" then
				-- одна форма покрывает и Proto Chunk Table, и карту опкодов,
				-- поэтому выгружаем оба среза
				local strs = dumpProtos(t, base)
				for _, s in ipairs(strs) do S.mainStrings[#S.mainStrings + 1] = s end
			elseif rec.kind == "REGISTERS" then
				dumpRegisters(t, base)
				harvestStrings(t, S.mainStrings, 0)
			elseif rec.kind == "NUMERIC_POOL" then
				dumpInstructions(t, base)
			elseif rec.kind == "MIXED_TABLE" then
				local strs = dumpConstPool(t, base)
				for _, s in ipairs(strs) do S.mainStrings[#S.mainStrings + 1] = s end
				dumpInstructions(t, base)
			else
				harvestStrings(t, S.mainStrings, 0)
			end
			pcall(S.installCallTracer, t, base)
		end
	end
	if #S.mainStrings > 0 then
		dumpFreq(S.mainStrings, "main/ALL_MAIN_STRINGS.txt",
			"ВСЕ СТРОКИ ИЗ СТРУКТУР VM (частота = сколько раз встречается)")
		S.log("main strings harvested: " .. #S.mainStrings)
	end
	if found > 0 then S.log("main dump written for " .. found .. " structures") end
	return found
end

-- Состояние виртуальных регистров самого интерпретатора (обычно большой upvalue)
function S.dumpVMState()
	local n = 0
	local seen = {}
	local function consider(fn, label, depth)
		if depth > 3 or type(fn) ~= "function" then return end
		local uvs = readUpvalues(fn)
		if type(uvs) ~= "table" then return end
		for i, uv in pairs(uvs) do
			if type(uv) == "table" then
				local a = taddr(uv)
				if not seen[a] then
					seen[a] = true
					local okc, cnt = pcall(function()
						local c = 0
						for _ in pairs(uv) do c = c + 1 end
						return c
					end)
					if okc and cnt >= S.cfg.minTableSize then
						local ok2, st = pcall(classify, uv)
						if ok2 and st then
							local nm = string.format("%s_uv%d_%s", label, tostring(i), st.kind)
							dumpRegisters(uv, nm)
							n = n + 1
						end
					end
				end
			end
		end
	end
	for _, fn in ipairs(S.seenFns or {}) do consider(fn, "vmfn", 0) end
	S.log("VM state dumps: " .. n)
	return n
end

---------------------------------------------------------------------------
-- 10.6 ПОЧИНКА СИНТАКСИСА
--      Перехваченные куски часто синтаксически битые: файл мог быть обрезан
--      на середине, строка не закрыта, блок не до конца. Валидируем
--      ОРИГИНАЛЬНЫМ компилятором (не нашим перехваченным load — иначе каждая
--      проверка попадёт в onChunk) и чиним по типам ошибок.
---------------------------------------------------------------------------
local function validate(src)
	local f = S.origCompiler or ORIG_COMPILER
	if type(f) ~= "function" then return nil, "compiler unavailable" end
	local ok, a, b = pcall(f, src, "=profes_check")
	if not ok then return false, tostring(a) end
	if a ~= nil then return true end
	return false, tostring(b)
end

-- Баланс блоков/скобок вне строк и комментариев + последняя "безопасная" точка
local function scanBalance(src)
	local stack = {}
	-- стек скобок: закрывать надо в ОБРАТНОМ порядке, иначе "f(g([3" ->
	-- ")))" вместо корректного "])"
	local bstack = {}
	local openParen, openBrack, openBrace = 0, 0, 0
	local unterminatedLong = nil
	local unterminatedQuote = nil
	local unterminatedQuotePos = nil
	local lastSafe = 0
	local i, n = 1, #src
	local expectThenForElseif = false

	local function skipStr(start)
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
			elseif ch == quote then return j + 1, true
			elseif ch == "\n" then return j, false
			else j = j + 1 end
		end
		return n + 1, false
	end

	while i <= n do
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
			if not e then
				unterminatedLong = close
				i = n + 1
			else
				i = e + #close
			end
		elseif c == '"' or c == "'" then
			local j, closed = skipStr(i)
			if not closed then
				unterminatedQuote = c
				unterminatedQuotePos = i
			end
			i = j
		elseif c:match("[%a_]") then
			local j = i
			while j <= n and src:sub(j, j):match("[%w_]") do j = j + 1 end
			local w = src:sub(i, j - 1)
			if w == "function" or w == "do" or w == "repeat" then
				stack[#stack + 1] = w
			elseif w == "then" then
				if expectThenForElseif then
					expectThenForElseif = false
				else
					stack[#stack + 1] = "if"
				end
			elseif w == "if" or w == "while" or w == "for" then
				expectThenForElseif = false
			elseif w == "elseif" then
				expectThenForElseif = true
			elseif w == "end" or w == "until" then
				table.remove(stack)
				expectThenForElseif = false
				if #stack == 0 and openParen == 0 and openBrack == 0 and openBrace == 0 then
					lastSafe = j
				end
			end
			i = j
		elseif c == "(" then
			openParen = openParen + 1
			bstack[#bstack + 1] = ")"
			i = i + 1
		elseif c == ")" then
			openParen = math.max(0, openParen - 1)
			if #bstack > 0 then table.remove(bstack) end
			i = i + 1
		elseif c == "[" then
			openBrack = openBrack + 1
			bstack[#bstack + 1] = "]"
			i = i + 1
		elseif c == "]" then
			openBrack = math.max(0, openBrack - 1)
			if #bstack > 0 then table.remove(bstack) end
			i = i + 1
		elseif c == "{" then
			openBrace = openBrace + 1
			bstack[#bstack + 1] = "}"
			i = i + 1
		elseif c == "}" then
			openBrace = math.max(0, openBrace - 1)
			if #bstack > 0 then table.remove(bstack) end
			i = i + 1
		else
			i = i + 1
		end
	end

	return {
		stack = stack, bstack = bstack,
		openParen = openParen, openBrack = openBrack, openBrace = openBrace,
		unterminatedLong = unterminatedLong, unterminatedQuote = unterminatedQuote,
		unterminatedQuotePos = unterminatedQuotePos,
		lastSafe = lastSafe,
	}
end

-- Пошаговая починка: закрываем строку, скобки, блоки — и после каждого шага
-- перепроверяем компилятором
local function repairSyntax(src, label)
	local fixes = {}
	local cur = src
	local bal = scanBalance(cur)

	-- Незакрытая обычная строка. Дописывать кавычку в конце файла нельзя
	-- (строка "съест" перевод строки), а обрезка по позиции кавычки оставляет
	-- "local s =" без значения. Поэтому отрезаем ВСЮ строку, на которой строка
	-- не закрыта: хвост после кавычки всё равно был частью строки, а не кодом.
	if bal.unterminatedQuote and bal.unterminatedQuotePos then
		local nlPos = nil
		for p = bal.unterminatedQuotePos - 1, 1, -1 do
			if cur:sub(p, p) == "\n" then nlPos = p break end
		end
		local cut = nlPos and cur:sub(1, nlPos) or ""
		if #cut < #cur then
			fixes[#fixes + 1] = string.format(
				"dropped incomplete line with unterminated string at pos %d (dropped %d bytes)",
				bal.unterminatedQuotePos, #cur - #cut)
			cur = cut
		end
	end
	if bal.unterminatedLong then
		cur = cur .. bal.unterminatedLong
		fixes[#fixes + 1] = "closed unterminated long string with '" .. bal.unterminatedLong .. "'"
	end

	local function fixBrackets()
		bal = scanBalance(cur)
		-- закрываем в обратном порядке, иначе для "f(g([3" получится ")))"
		local add = {}
		for k = #bal.bstack, 1, -1 do add[#add + 1] = bal.bstack[k] end
		if #add > 0 then
			cur = cur .. table.concat(add)
			fixes[#fixes + 1] = "appended " .. #add .. " closing bracket(s): " .. table.concat(add)
			return true
		end
		return false
	end

	local function fixBlocks()
		bal = scanBalance(cur)
		if #bal.stack == 0 then return false end
		local add = {}
		for k = #bal.stack, 1, -1 do
			-- "until" требует условия, голое "until" невалидно
			add[#add + 1] = (bal.stack[k] == "repeat") and "until true" or "end"
		end
		cur = cur .. "\n" .. table.concat(add, "\n") .. "\n"
		fixes[#fixes + 1] = "appended " .. #add .. " block closer(s): " .. table.concat(add, " ")
		return true
	end

	fixBrackets()
	fixBlocks()

	local ok, err = validate(cur)
	if ok == nil then return cur, fixes, nil, err end
	local iter = 0
	while not ok and iter < 6 do
		iter = iter + 1
		local progress = false
		progress = fixBrackets() or progress
		ok, err = validate(cur)
		if ok then break end
		progress = fixBlocks() or progress
		ok, err = validate(cur)
		if not progress then break end
	end

	-- последний шанс: обрезать до последней целой верхнеуровневой конструкции
	if not ok and S.cfg.salvage then
		bal = scanBalance(cur)
		if bal.lastSafe > 0 and bal.lastSafe < #cur then
			local cut = cur:sub(1, bal.lastSafe)
			local ok2, err2 = validate(cut)
			if ok2 then
				cur = cut
				fixes[#fixes + 1] = "salvaged: truncated to last complete statement ("
					.. bal.lastSafe .. " bytes)"
				ok, err = true, nil
			else
				-- обрезанный кусок тоже может требовать закрытия
				fixBrackets()
				fixBlocks()
				local ok3 = validate(cur)
				if ok3 then
					fixes[#fixes + 1] = "salvaged: truncated to " .. bal.lastSafe .. " bytes then closed blocks"
					ok, err = true, nil
				end
			end
		end
	end

	return cur, fixes, ok, err
end

S.fixLog = {}
function S.fixReport(line)
	S.fixLog[#S.fixLog + 1] = line
	if #S.fixLog > 400 then table.remove(S.fixLog, 1) end
end

function S.flushFixes()
	if #S.fixLog > 0 then
		S.save("syntax_fixes.txt", table.concat(S.fixLog, "\n") .. "\n")
	end
end

-- Проверяет текст и, если он не компилируется, чинит и пишет .fixed.lua
function S.ensureValid(base, text, kind)
	if type(text) ~= "string" or #text < 2 then return end
	local ok, err = validate(text)
	if ok == nil then
		-- компилятора нет: чинить вслепую нельзя, только сообщить
		S.fixReport("=== " .. base .. "." .. kind .. " ===\n  skipped: " .. tostring(err))
		return
	end
	if ok then return true end
	local fixed, fixes, ok2, err2 = repairSyntax(text, base .. "." .. kind)
	S.fixReport(string.format("=== %s.%s ===\n  error: %s\n  fixes: %s\n  result: %s",
		base, kind, tostring(err),
		(#fixes > 0) and table.concat(fixes, " | ") or "(none)",
		ok2 and "COMPILES" or ("still broken: " .. tostring(err2))))
	S.log("syntax broken in " .. base .. "." .. kind .. " -> " ..
		(#fixes > 0) and (#fixes .. " fix(es)") or "no fix")
	if ok2 then
		S.save(base .. "." .. kind .. ".fixed.lua", fixed)
	end
	return ok2, err2
end

---------------------------------------------------------------------------
-- 10.7 BRUTAL: глубокий обход памяти + живая расшифровка + реконструктор
--      ГЛАВНОГО СКРИПТА (любой скрипт из памяти — фулл деобфусцированный)
---------------------------------------------------------------------------
-- Глубокий сбор: getgc(includeTables) + getrenv + _G/getgenv/shared +
-- рекурсия по upvalue до deepDepth. Цепляет то, что мелкий обход не видел:
-- зашифрованные blob-строки, вложенные VM-таблицы, скрытые прототипы.
function S.collectDeep()
	if not S.cfg.brutal then return {}, {} end
	local seenT, outT = {}, {}
	local seenF, outF = {}, {}
	local nT, nF = 0, 0
	local maxT = S.cfg.maxDeepTables or 60000
	local maxF = S.cfg.maxFns or 60000

	local function addT(t)
		if type(t) ~= "table" then return end
		if isSelfTable(t) then return end
		local a = taddr(t)
		if seenT[a] then return end
		seenT[a] = true
		nT = nT + 1
		if nT <= maxT then outT[#outT + 1] = t end
	end

	local wDeepT, wDeepF
	wDeepT = function(t, depth)
		if depth > (S.cfg.deepDepth or 8) then return end
		if nT > maxT then return end
		local ok = pcall(pairs, t)
		if not ok then return end
		for k, v in pairs(t) do
			local tv = type(v)
			if tv == "table" then
				addT(v)
				wDeepT(v, depth + 1)
			elseif tv == "function" then
				wDeepF(v, depth + 1)
			elseif tv == "string" and #v >= (S.cfg.blobMin or 512) then
				-- кандидат в зашифрованный blob: длинная строка с мусором
				local a = "blob_" .. hashStr(v)
				if not S.blobs[a] and #S.blobs < 200 then
					S.blobs[a] = { len = #v, head = v:sub(1, 64) }
					S.save("deep/blob_" .. a .. ".bin", v)
					S.save("deep/blob_" .. a .. ".info.txt",
						"-- blob len=" .. #v .. "\n-- HEX[0..63]:\n" .. hexDump(v, 64) .. "\n")
				end
			end
			if type(k) == "string" and #k >= (S.cfg.blobMin or 512) then
				local a = "blobk_" .. hashStr(k)
				if not S.blobs[a] and #S.blobs < 200 then
					S.blobs[a] = { len = #k, head = k:sub(1, 64) }
					S.save("deep/blob_" .. a .. ".bin", k)
				end
			end
		end
	end

	wDeepF = function(fn, depth)
		if type(fn) ~= "function" then return end
		if isSelfFn(fn) then return end
		if depth > (S.cfg.deepDepth or 8) then return end
		local key = taddr(fn)
		if seenF[key] then return end
		seenF[key] = true
		nF = nF + 1
		if nF <= maxF then outF[#outF + 1] = fn end
		if nF > maxF then return end
		S.fnCount = S.fnCount + 1
		local getupval = rawget(genv, "getupvalues") or rawget(_G, "getupvalues")
		if type(getupval) == "function" then
			local ok, uvs = pcall(getupval, fn)
			if ok and type(uvs) == "table" then
				for _, uv in pairs(uvs) do
					if type(uv) == "table" then
						addT(uv)
						wDeepT(uv, depth + 1)
					elseif type(uv) == "function" then
						wDeepF(uv, depth + 1)
					elseif type(uv) == "string" and #uv >= (S.cfg.blobMin or 512) then
						local a = "blob_" .. hashStr(uv)
						if not S.blobs[a] and #S.blobs < 200 then
							S.blobs[a] = { len = #uv, head = uv:sub(1, 64) }
							S.save("deep/blob_" .. a .. ".bin", uv)
						end
					end
				end
			end
		end
		-- поля функции (наш хук держит orig)
		for _, field in ipairs({"__profesBase"}) do
			local ok2, v = pcall(function() return fn[field] end)
			if ok2 and type(v) == "table" then addT(v) wDeepT(v, depth + 1) end
		end
	end

	-- 1) getgc с таблицами (там живут Constant Pool / Instruction Array)
	local getgcFn = rawget(genv, "getgc") or rawget(_G, "getgc")
	if type(getgcFn) == "function" then
		for _, inc in ipairs({true, false}) do
			local ok, res = pcall(getgcFn, inc)
			if ok and type(res) == "table" then
				for _, v in ipairs(res) do
					if type(v) == "table" then addT(v)
					elseif type(v) == "function" then wDeepF(v, 0) end
				end
			end
			-- без аргументов (некоторые реализации)
			if inc then
				local ok0, res0 = pcall(getgcFn)
				if ok0 and type(res0) == "table" then
					for _, v in ipairs(res0) do
						if type(v) == "table" then addT(v)
						elseif type(v) == "function" then wDeepF(v, 0) end
					end
				end
			end
		end
	end

	-- 2) корневые окружения: _G / getgenv / shared / getrenv / registry
	for _, root in ipairs({_G, genv}) do
		if type(root) == "table" then addT(root) wDeepT(root, 0) end
	end
	local sh = rawget(genv, "shared")
	if type(sh) == "table" then addT(sh) wDeepT(sh, 1) end
	local okR, renv = pcall(function()
		if type(getrenv) == "function" then return getrenv() end
	end)
	if okR and type(renv) == "table" then addT(renv) wDeepT(renv, 1) end
	local okReg, reg = pcall(function()
		if type(getregistry) == "function" then return getregistry() end
	end)
	if okReg and type(reg) == "table" then addT(reg) wDeepT(reg, 1) end

	-- 3) наши хуки + функции chunk'ов (точка входа в VM)
	for _, name in ipairs({"loadstring", "load"}) do
		local h = rawget(genv, name) or rawget(_G, name)
		if type(h) == "function" then wDeepF(h, 0) end
	end
	for _, fn in ipairs(S.chunkFns or {}) do wDeepF(fn, 0) end
	for _, fn in ipairs(S.seenFns or {}) do wDeepF(fn, 0) end

	S.deepCount = nT
	S.log("deep collect: tables=" .. nT .. " fns=" .. nF .. " blobs=" .. #S.blobs)
	return outT, outF
end

-- Живой перехват расшифровки: VM гоняет константы через string.byte/char/sub
-- и table.insert/concat. Хуки фиксируют длинные осмысленные строки в момент,
-- когда они появляются РАСШИФРОВАННЫМИ в рантайме. Только чтение аргументов,
-- поведение оригинала не меняется.
local function hookLiveFn(holder, name, onCall)
	if type(holder) ~= "table" then return end
	local cur = rawget(holder, name)
	if type(cur) ~= "function" then return end
	if isOurHook(cur) then return end
	local wrapper = function(...)
		local r = table.pack(cur(...))
		pcall(onCall, table.pack(...), r)
		return table.unpack(r, 1, r.n)
	end
	tagHook(wrapper, cur)
	pcall(rawset, holder, name, makeNative(wrapper))
end

function S.installLiveDecrypt()
	if not S.cfg.liveDecrypt then return end
	if S.liveInstalled then return end
	S.liveInstalled = true
	local function noteStr(s, tag)
		if type(s) ~= "string" then return end
		if #s < 3 or #s > 4000 then return end
		-- было 3 буквы подряд — резало короткие игровые ключи ("Gui", "Pet");
		-- теперь мягче: хоть 2 буквы/цифры и без нулей
		if not s:find("[%a][%a]") and not s:find("[%a]%d") then return end
		if s:find("\0", 1, true) then return end
		local h = hashStr(s)
		if S.decryptedSeen[h] then return end
		if #S.decrypted > 40000 then return end
		S.decryptedSeen[h] = true
		S.decrypted[#S.decrypted + 1] = { tag = tag, s = s }
	end
	local function scanArgs(a)
		for i = 1, a.n do
			noteStr(a[i], "arg")
			-- таблицы-аргументы: дёргаем строки изнутри (константы пачками)
			if type(a[i]) == "table" then
				local ok = pcall(function()
					for _, vv in pairs(a[i]) do noteStr(vv, "argtbl") end
				end)
				if not ok then break end
			end
		end
	end
	local function scanRes(r)
		for i = 1, r.n do
			noteStr(r[i], "ret")
			if type(r[i]) == "table" then
				local ok = pcall(function()
					for _, vv in pairs(r[i]) do noteStr(vv, "rettbl") end
				end)
				if not ok then break end
			end
		end
	end
	-- ШИРОКИЙ НЕВОД: всё, чем VM может собирать строки при расшифровке.
	-- Каждый хук только ЧИТАЕТ аргументы/результат, поведение не меняет.
	pcall(hookLiveFn, string, "char", function(a, r) scanRes(r) end)
	pcall(hookLiveFn, string, "sub", function(a, r) scanRes(r) scanArgs(a) end)
	pcall(hookLiveFn, string, "rep", function(a, r) scanRes(r) end)
	pcall(hookLiveFn, string, "format", function(a, r) scanRes(r) scanArgs(a) end)
	pcall(hookLiveFn, string, "gsub", function(a, r) scanRes(r) end)
	pcall(hookLiveFn, string, "lower", function(a, r) scanRes(r) end)
	pcall(hookLiveFn, string, "upper", function(a, r) scanRes(r) end)
	pcall(hookLiveFn, string, "reverse", function(a, r) scanRes(r) end)
	pcall(hookLiveFn, string, "byte", function(a, r) scanArgs(a) end)
	pcall(hookLiveFn, table, "concat", function(a, r) scanRes(r) scanArgs(a) end)
	pcall(hookLiveFn, table, "insert", function(a, r) scanArgs(a) end)
	pcall(hookLiveFn, table, "unpack", function(a, r) scanRes(r) end)
	if type(table.pack) == "function" then
		pcall(hookLiveFn, table, "pack", function(a, r) scanArgs(a) end)
	end
	-- buffer: VM таскает байткод/константы через него
	local bufH = rawget(_G, "buffer") or rawget(genv, "buffer")
	if type(bufH) == "table" then
		pcall(hookLiveFn, bufH, "tostring", function(a, r) scanRes(r) end)
		pcall(hookLiveFn, bufH, "readstring", function(a, r) scanRes(r) end)
	end
	-- bit32: сами по себе строк не дают, но их аргументы — индексы в пулы;
	-- не хукаем (шум), вместо этого хукаем tostring/tonumber на выходах
	pcall(hookLiveFn, _G, "tostring", function(a, r) scanRes(r) end)
	S.log("live decrypt hooks installed (string.* x9, table.* x4, buffer, tostring)")
end

function S.flushDecrypted()
	if #S.decrypted == 0 then return end
	local out = { "=== DECRYPTED CONSTANTS (пойманы живой расшифровкой в рантайме) ===",
		"Это строки, которых НЕТ в статическом Constant Pool — VM", "расшифровала их при исполнении.",
		"" }
	for _, e in ipairs(S.decrypted) do
		out[#out + 1] = string.format("[%s] %q", e.tag, e.s)
	end
	S.save("main/DECRYPTED_CONSTANTS.txt", table.concat(out, "\n") .. "\n")
end

-- ВЫЖИМАЛКА: каждый свип дёргает строки из живых таблиц VM (регистры,
-- upvalue-хранилища) и константы всех известных функций через readConstants.
-- Это главный источник ИГРОВЫХ строк: пулы шифрованы, а в работе VM строки
-- лежат расшифрованными в регистрах и upvalue.
function S.harvestLive()
	local got = 0
	local function eatStr(s)
		if type(s) ~= "string" then return end
		if #s < 2 or #s > 4000 then return end
		if s:find("\0", 1, true) then return end
		if not s:find("[%a]") then return end
		if #S.mainStrings > (S.cfg.maxDumpStrings or 20000) then return end
		S.mainStrings[#S.mainStrings + 1] = s
		got = got + 1
	end
	local function eatTable(t, depth)
		if depth > 3 or #S.mainStrings > (S.cfg.maxDumpStrings or 20000) then return end
		local ok = pcall(pairs, t)
		if not ok then return end
		for k, v in pairs(t) do
			if type(v) == "string" then eatStr(v)
			elseif type(v) == "table" then eatTable(v, depth + 1)
			end
			if type(k) == "string" and #k > 2 and #k < 200 then eatStr(k) end
		end
	end
	-- 1) все уже найденные структуры: выжать строки изнутри
	for _, rec in ipairs(S.mainStructs or {}) do
		if rec.t and type(rec.t) == "table" then eatTable(rec.t, 0) end
	end
	-- 2) upvalue всех известных функций (там регистры диспетчера)
	for _, fn in ipairs(S.seenFns or {}) do
		local uvs = readUpvalues(fn)
		if type(uvs) == "table" then
			for _, uv in pairs(uvs) do
				if type(uv) == "string" then eatStr(uv)
				elseif type(uv) == "table" then eatTable(uv, 0) end
			end
		end
		-- 3) константы каждой функции (расшифрованные Luau-константы)
		local cs = readConstants(fn)
		if type(cs) == "table" then
			for _, c in pairs(cs) do
				if type(c) == "string" then eatStr(c) end
			end
		end
	end
	return got
end

-- ECR-декодер: контейнер "\27LUA" + байт-ключ + EOR-поток (как в script_memory)
local function decodeEor(data, key, startIdx, variant)
	local n = #data
	if n < startIdx + 8 then return nil end
	local out = {}
	local prev = key
	for i = startIdx, n do
		local b = data:byte(i)
		local v
		if i == startIdx and variant == 2 then v = prev
		else v = (b + prev) % 256 prev = v end
		out[#out + 1] = string.char(v)
	end
	return table.concat(out)
end

local function ecrScore(d)
	if #d < 8 then return -999 end
	local score = 0
	for i = 1, 6 do
		local b = d:byte(i)
		if b and b <= 16 then score = score + 2 else score = score - 8 end
	end
	local sample = math.min(#d, 1024)
	local printable = 0
	for i = 1, sample do
		local b = d:byte(i)
		if b >= 32 and b < 127 then printable = printable + 1 end
	end
	return score + (printable / sample) * 6
end

function S.tryEcrDecode(data)
	if not S.cfg.ecr then return nil end
	if type(data) ~= "string" or #data < 40 then return nil end
	if data:sub(1, 4) ~= "\27LUA" then return nil end
	local head = data:sub(1, 4096)
	local keys = {0x5D, 0x5B, 0x5C, 0x5E, 0x09, 0x2A, 0x11, 0x37, 0x00, 0xFF,
		data:byte(4), data:byte(5), data:byte(6)}
	local best, bK, bS, bV = -math.huge, nil, nil, nil
	for _, key in ipairs(keys) do
		for s = 5, 6 do
			for v = 1, 2 do
				local d = decodeEor(head, key, s, v)
				if d then
					local sc = ecrScore(d)
					if sc > best then best, bK, bS, bV = sc, key, s, v end
				end
			end
		end
	end
	if best < 11 or not bK then return nil end
	local full = decodeEor(data, bK, bS, bV)
	if not full then return nil end
	local info = string.format("key=0x%02X start=%d variant=%d score=%.1f", bK, bS, bV, best)
	S.ecrInfo[#S.ecrInfo + 1] = info
	return full, info
end

function S.tryEcrOnBinary(base, data)
	local dec, info = S.tryEcrDecode(data)
	if dec then
		S.save(base .. ".ecr.lua", "-- ECR auto-decoded: " .. tostring(info) .. "\n" .. dec)
		S.log("ECR decoded: " .. tostring(info) .. " -> " .. base .. ".ecr.lua")
		return true
	end
	return false
end

-- Дерево прототипов через getprotos/getconstants/getupvalues по всем функциям.
-- Даёт структуру ГЛАВНОГО скрипта: какие функции внутри каких.
function S.buildClosureTree(fns)
	if not S.cap.getprotos and not (type(debug) == "table" and type(debug.getproto) == "function") then
		-- на части мобильных экзекуторов проtos недоступны: пропускаем молча,
		-- реконструктор всё равно соберётся из пулов и инструкций
		return
	end
	local visited = {}
	local out = S.closureTree
	local function walk(fn, depth)
		if type(fn) ~= "function" or depth > 10 then return end
		local k = taddr(fn)
		if visited[k] then return end
		visited[k] = true
		local pad = string.rep("  ", depth)
		local info = {}
		if type(debug) == "table" and type(debug.getinfo) == "function" then
			pcall(function() info = debug.getinfo(fn, "Su") or {} end)
		end
		out[#out + 1] = string.format("%sfn L%s..%s params=%s vararg=%s",
			pad, tostring(info.linedefined or "?"), tostring(info.lastlinedefined or "?"),
			tostring(info.nparams or "?"), tostring(info.isvararg))
		do
			local cs = readConstants(fn)
			if type(cs) == "table" then
				local parts = {}
				for _, c in pairs(cs) do
					if type(c) == "string" and #c > 1 and #parts < 24 then
						parts[#parts + 1] = string.format("%q", c:sub(1, 48))
					elseif (type(c) == "number" or type(c) == "boolean") and #parts < 24 then
						parts[#parts + 1] = tostring(c)
					end
				end
				if #parts > 0 then out[#out + 1] = pad .. "  consts: " .. table.concat(parts, ", ") end
			end
		end
		do
			local uvs = readUpvalues(fn)
			if type(uvs) == "table" then
				local names = {}
				for kk, uv in pairs(uvs) do
					if type(uv) == "function" then
						if #names < 20 then names[#names + 1] = tostring(kk) .. ":fn" end
					elseif #names < 20 then
						names[#names + 1] = tostring(kk) .. ":" .. type(uv)
					end
				end
				if #names > 0 then out[#out + 1] = pad .. "  upvals: " .. table.concat(names, ", ") end
				for _, uv in pairs(uvs) do
					if type(uv) == "function" then walk(uv, depth + 1) end
				end
			end
		end
		do
			local protos = readProtos(fn)
			if type(protos) == "table" then
				local list = {}
				for kk, vv in pairs(protos) do
					if type(vv) == "function" then list[#list + 1] = vv end
				end
				if #list > 0 then out[#out + 1] = pad .. "  protos: " .. #list end
				for _, p in ipairs(list) do walk(p, depth + 1) end
			end
		end
	end
	for _, fn in ipairs(fns or S.seenFns or {}) do walk(fn, 0) end
	if #out > 0 then
		S.save("main/closure_tree.txt", table.concat(out, "\n") .. "\n")
	end
end

-- РЕКОНСТРУКТОР: собирает ОДИН читаемый main/FULL_DEOBFUSCATED.lua из всего,
-- что VM держит в памяти. Это и есть "главный скрипт фулл деобфусцированный":
-- пулы констант с индексами, прототипы с константами, псевдокод инструкций
-- через карту опкодов, живые регистры, closure-дерево, все строки + живая
-- расшифровка. Опкоды рандомизированы, поэтому инструкции идут псевдокодом
-- "OP_<hex>(...)" с подсказкой из inferOpcode — честнее, чем выдуманный Lua.
function S.buildFullDeobfuscated()
	local L = {}
	L[#L + 1] = "--[[══════════════════════════════════════════════════"
	L[#L + 1] = "  FULL DEOBFUSCATED — главный скрипт, собран из памяти VM"
	L[#L + 1] = "  дата: " .. os.date("%Y-%m-%d %H:%M:%S")
	L[#L + 1] = "  структур: " .. tostring(#(S.mainStructs or {}))
	L[#L + 1] = "  опкоды рандомизированы: инструкции — псевдокод OP_<hex>"
	L[#L + 1] = "  сопоставление: opcodes.txt + chunk_*.pretty.lua по 'line N'"
	L[#L + 1] = "══════════════════════════════════════════════════]]"
	L[#L + 1] = ""
	local nPool, nInstr, nProto, nState = 0, 0, 0, 0

	for idx, rec in ipairs(S.mainStructs or {}) do
		local t = rec.t
		if t then
			local kind = rec.kind
			if kind == "CONSTANT_POOL" or kind == "MIXED_TABLE" or kind == "NUMERIC_POOL" then
				nPool = nPool + 1
				L[#L + 1] = string.format("-- ━━━ CONSTANT POOL #%d (main/%03d_%s) ━━━", nPool, idx, kind)
				L[#L + 1] = "local K" .. nPool .. " = {"
				local idxs = {}
				for k in pairs(t) do if type(k) == "number" then idxs[#idxs + 1] = k end end
				table.sort(idxs)
				for _, k in ipairs(idxs) do
					if #L > 120000 then break end
					local v = t[k]
					local tv = type(v)
					if tv == "string" then
						L[#L + 1] = string.format("\t[%d] = %q,", k, v)
					elseif tv == "number" or tv == "boolean" then
						L[#L + 1] = string.format("\t[%d] = %s,", k, tostring(v))
					elseif tv == "table" then
						local parts = {}
						for kk, vv in pairs(v) do
							if #parts >= 8 then break end
							parts[#parts + 1] = tostring(kk) .. "=" .. vstr(vv, 30)
						end
						L[#L + 1] = string.format("\t[%d] = { %s },", k, table.concat(parts, ", "))
					else
						L[#L + 1] = string.format("\t[%d] = <%s>,", k, tv)
					end
				end
				L[#L + 1] = "}"
				L[#L + 1] = ""
			elseif kind == "FUNC_TABLE" then
				nProto = nProto + 1
				L[#L + 1] = string.format("-- ━━━ PROTO TABLE #%d (main/%03d_%s) ━━━", nProto, idx, kind)
				local keys = {}
				for k in pairs(t) do keys[#keys + 1] = k end
				table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
				for _, k in ipairs(keys) do
					if #L > 120000 then break end
					local v = t[k]
					if type(v) == "function" then
						local info = {}
						if type(debug) == "table" and type(debug.getinfo) == "function" then
							pcall(function() info = debug.getinfo(v, "Su") or {} end)
						end
						L[#L + 1] = string.format("-- proto[%s] params=%s vararg=%s src_line=%s",
							tostring(k), tostring(info.nparams or "?"),
							tostring(info.isvararg), tostring(info.linedefined or "?"))
						L[#L + 1] = string.format("local function PROTO_%s()",
							tostring(k):gsub("[^%w]", "_"))
						do
							local cs = readConstants(v)
							if type(cs) == "table" then
								for _, c in pairs(cs) do
									local tc = type(c)
									if tc == "string" and #c > 0 then
										L[#L + 1] = string.format("\t-- const %q", c:sub(1, 120))
									elseif tc == "number" or tc == "boolean" then
										L[#L + 1] = string.format("\t-- const %s", tostring(c))
									end
									if #L > 120000 then break end
								end
							end
						end
						do
							local uvs = readUpvalues(v)
							if type(uvs) == "table" then
								for kk, uv in pairs(uvs) do
									local tu = type(uv)
									if tu == "string" then
										L[#L + 1] = string.format("\t-- upval %s = %q", tostring(kk), uv:sub(1, 100))
									elseif tu == "number" or tu == "boolean" then
										L[#L + 1] = string.format("\t-- upval %s = %s", tostring(kk), tostring(uv))
									else
										L[#L + 1] = string.format("\t-- upval %s: <%s>", tostring(kk), tu)
									end
								end
							end
						end
						L[#L + 1] = "end"
						L[#L + 1] = ""
					end
				end
			elseif kind == "INSTRUCTION_ARRAY" then
				nInstr = nInstr + 1
				L[#L + 1] = string.format("-- ━━━ INSTRUCTIONS #%d (main/%03d_%s, псевдокод) ━━━", nInstr, idx, kind)
				L[#L + 1] = "-- формат: PC  OP_<hex>(операнды)  -- подсказка + K[индекс]=строка из пулов"
				-- карта opcode -> label из уже собранного opcodeOut
				local opLabel = {}
				for _, line in ipairs(S.opcodeOut or {}) do
					local num, label = line:match("%((%d+)%)%s+line%s+%S+%s+(%S+)")
					if num then opLabel[tonumber(num)] = label end
				end
				-- УЯЗВИМОСТЬ: операнды инструкций — это ИНДЕКСЫ в Constant Pool.
				-- Строим общий индекс пулов: число -> строка, чтобы подставлять
				-- K[n]="..." прямо в псевдокод. Это превращает OP_0xHH(17,42)
				-- в читаемое OP_0xHH(K17="FireServer", K42="...").
				if not S.poolIndex then
					S.poolIndex = {}
					for _, rec2 in ipairs(S.mainStructs or {}) do
						local t2 = rec2.t
						if t2 and (rec2.kind == "CONSTANT_POOL" or rec2.kind == "MIXED_TABLE" or rec2.kind == "NUMERIC_POOL") then
							for k2, v2 in pairs(t2) do
								if type(k2) == "number" and type(v2) == "string"
									and #v2 >= 2 and #v2 <= 300 and S.poolIndex[k2] == nil then
									S.poolIndex[k2] = v2
								end
							end
						end
					end
				end
				local idxs = {}
				for k in pairs(t) do if type(k) == "number" then idxs[#idxs + 1] = k end end
				table.sort(idxs)
				for _, k in ipairs(idxs) do
					if #L > 120000 then L[#L + 1] = "-- << truncated >>" break end
					local v = t[k]
					if type(v) == "table" then
						local op, rest = nil, {}
						for kk, vv in pairs(v) do
							if (kk == 1 or kk == "op" or kk == "opcode") and type(vv) == "number" then
								op = vv
							else
								-- операнд-число: пробуем разрешить через пул
								if type(vv) == "number" and S.poolIndex and S.poolIndex[vv] then
									if #rest < 8 then rest[#rest + 1] = string.format("%s=K%d=%q", tostring(kk), vv, S.poolIndex[vv]:sub(1, 40)) end
								else
									if #rest < 8 then rest[#rest + 1] = tostring(kk) .. "=" .. vstr(vv, 30) end
								end
							end
						end
						if op then
							local hint = opLabel[op % 256] or opLabel[op] or "?"
							L[#L + 1] = string.format("  [%d] OP_0x%02X(%s) -- %s", k, op % 256,
								table.concat(rest, ", "), hint)
						else
							L[#L + 1] = string.format("  [%d] { %s }", k, table.concat(rest, ", "))
						end
					else
						L[#L + 1] = string.format("  [%d] = %s", k, vstr(v, 80))
					end
				end
				L[#L + 1] = ""
			elseif kind == "REGISTERS" then
				nState = nState + 1
				L[#L + 1] = string.format("-- ━━━ LIVE STATE #%d (main/%03d_%s) ━━━", nState, idx, kind)
				local idxs = {}
				for k in pairs(t) do if type(k) == "number" then idxs[#idxs + 1] = k end end
				table.sort(idxs)
				for _, k in ipairs(idxs) do
					if #L > 120000 then break end
					local v = t[k]
					if type(v) == "string" then
						L[#L + 1] = string.format("-- R[%d] = %q", k, v:sub(1, 100))
					else
						L[#L + 1] = string.format("-- R[%d] = %s", k, vstr(v, 80))
					end
				end
				L[#L + 1] = ""
			end
		end
	end

	-- живая расшифровка отдельным блоком
	if #S.decrypted > 0 then
		L[#L + 1] = "-- ━━━ DECRYPTED AT RUNTIME (" .. #S.decrypted .. ") ━━━"
		for _, e in ipairs(S.decrypted) do
			if #L > 125000 then break end
			L[#L + 1] = string.format("-- [%s] %q", e.tag, e.s)
		end
		L[#L + 1] = ""
	end

	-- closure-дерево отдельным блоком
	if #S.closureTree > 0 then
		L[#L + 1] = "-- ━━━ CLOSURE TREE (getprotos) ━━━"
		for _, line in ipairs(S.closureTree) do
			if #L > 125000 then break end
			L[#L + 1] = "-- " .. line
		end
		L[#L + 1] = ""
	end

	L[#L + 1] = string.format("-- pools=%d protos=%d instr=%d states=%d decrypted=%d",
		nPool, nProto, nInstr, nState, #S.decrypted)
	local text = table.concat(L, "\n") .. "\n"
	S.save("main/FULL_DEOBFUSCATED.lua", text)
	-- валидация собранного файла оригинальным компилятором
	if S.cfg.fixSyntax then pcall(S.ensureValid, "main/FULL_DEOBFUSCATED", text, "lua") end
	S.log(string.format("FULL_DEOBFUSCATED written: %d bytes pools=%d protos=%d instr=%d",
		#text, nPool, nProto, nInstr))
	return #text
end

-- BRUTAL-скан: глубокий сбор + классификация всего + дерево + реконструктор.
-- Вызывается из scheduleScan цепочкой и из PROFES_SCAN / PROFES_MAIN.
function S.brutalScan()
	if not S.cfg.brutal then return 0 end
	pcall(S.installLiveDecrypt)
	local deepT, deepF = S.collectDeep()
	local found = 0
	-- классифицируем глубокие таблицы (порог ниже — цепляем средние пулы)
	for _, t in ipairs(deepT) do
		local a = taddr(t)
		if not S.structs[a] then
			local ok, st = pcall(classify, t)
			if ok and st and st.kind == "SELF" then
				S.structs[a] = st
			elseif ok and st then
				S.structs[a] = st
				if st.total >= math.min(S.cfg.minTableSize, 8) and st.kind ~= "SMALL" and st.kind ~= "EMPTY" then
					S.scanned = S.scanned + 1
					found = found + 1
					pcall(dumpStructure, S.scanned, t, st)
					S.mainStructs[#S.mainStructs + 1] = { t = t, kind = st.kind, stat = st }
				end
			end
		end
	end
	-- функции из глубокого сбора — в общий пул для dumpVMState/closure-дерева
	for _, fn in ipairs(deepF) do S.seedFromFunction(fn) end
	pcall(S.buildClosureTree, deepF)
	-- ВЫЖИМАЛКА: строки из живых регистров + константы функций — каждый проход
	local okH, gotH = pcall(S.harvestLive)
	if okH and type(gotH) == "number" and gotH > 0 then
		S.log("harvestLive: +" .. gotH .. " strings (total " .. #S.mainStrings .. ")")
	end
	pcall(S.flushDecrypted)
	-- ECR по всем бинарным chunk'ам (повторно безопасно: перезаписывает тем же)
	for _, c in ipairs(S.chunks or {}) do
		if c.binary and c.raw then pcall(S.tryEcrOnBinary, c.ecrBase, c.raw) end
	end
	S.poolIndex = nil -- пулы обновились: индекс перестроить при сборке FULL
	pcall(S.buildFullDeobfuscated)
	if #S.structIndex > 0 then
		S.save("structures_index.txt", table.concat(S.structIndex, "\n") .. "\n")
	end
	return found
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
	pcall(S.installLiveDecrypt)
	S.log("hooks installed: " .. hookCount)
	return hookCount
end

installAll()
S.flush()
-- MOBILE: долгий опрос памяти стартует сам — на телефоне структуры VM
-- появляются поздно, одного свипа не хватает. Плюс capability-строка в лог.
S.save("capabilities.txt", (function()
	local c = S.cap
	local ks = {}
	for k in pairs(c) do ks[#ks + 1] = k end
	table.sort(ks)
	local o = { "=== EXECUTOR CAPABILITIES ===" }
	for _, k in ipairs(ks) do o[#o + 1] = string.format("  %-16s %s", k, tostring(c[k])) end
	return table.concat(o, "\n") .. "\n"
end)())
pcall(S.startMobilePoller)

---------------------------------------------------------------------------
-- 13. РУЧНЫЕ КОМАНДЫ
---------------------------------------------------------------------------
genv.PROFES_STATUS = function()
	return string.format("dir=%s chunks=%d structures=%d sweeps=%d hooks=%d",
		tostring(S.dir), S.counter, S.scanned, S.sweepCount, hookCount)
end

genv.PROFES_SCAN = function()
	local n = S.scanStructures()
	pcall(S.brutalScan)
	S.flush()
	print("[Profes] structures found: " .. tostring(n) .. " | " .. genv.PROFES_STATUS())
	return n
end

-- принудительная выгрузка main-скрипта из уже найденных структур
genv.PROFES_MAIN = function()
	S.mainStrings = {}
	local n = S.dumpMain()
	local m = S.dumpVMState()
	local b = 0
	if S.cfg.brutal then
		local deepT, deepF = S.collectDeep()
		for _, t in ipairs(deepT) do
			local a = taddr(t)
			if not S.structs[a] then
				local ok, st = pcall(classify, t)
				if ok and st and st.total >= 8 and st.kind ~= "SMALL" and st.kind ~= "EMPTY" then
					S.structs[a] = st
					S.mainStructs[#S.mainStructs + 1] = { t = t, kind = st.kind, stat = st }
				end
			end
		end
		for _, fn in ipairs(deepF) do S.seedFromFunction(fn) end
		pcall(S.buildClosureTree, deepF)
		local okB, resB = pcall(S.buildFullDeobfuscated)
		if okB and type(resB) == "number" then b = resB end
	end
	pcall(S.flushDecrypted)
	S.flush()
	print("[Profes] main dumped from " .. tostring(n) .. " structures, VM state tables: " .. tostring(m)
		.. ", full bytes=" .. tostring(b))
	return n
end

-- полный фулл-дамп одной командой: скан + brutal + main + flush
genv.PROFES_FULL = function()
	pcall(S.scanStructures)
	pcall(S.brutalScan)
	S.mainStrings = {}
	pcall(S.dumpMain)
	pcall(S.dumpVMState)
	local b = pcall(S.buildFullDeobfuscated)
	pcall(S.flushDecrypted)
	S.flush()
	pcall(S.flushFixes)
	print("[Profes] FULL done | " .. genv.PROFES_STATUS() .. " | main/FULL_DEOBFUSCATED.lua")
	return S.dir
end

genv.PROFES_CAPS = function()
	for k, v in pairs(S.cap) do print("  " .. tostring(k) .. " = " .. tostring(v)) end
	return S.cap
end

genv.PROFES_VMSTATE = function()
	local n = S.dumpVMState()
	S.flush()
	print("[Profes] VM state tables: " .. tostring(n))
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
print("  SCRIPT-PROFES v2 BRUTAL+MOBILE - RUNNING")
print("  folder: workspace/" .. S.dir)
print("  hooks: " .. hookCount)
print("  mobile Hollow: getgc=" .. tostring(S.cap.getgc)
	.. " protos=" .. tostring(S.cap.getprotos)
	.. " consts=" .. tostring(S.cap.getconstants)
	.. " upvals=" .. tostring(S.cap.canUpvals))
print("  1) run your obfuscated script / loadstring")
print("  2) sweeps run automatically, or PROFES_SCAN() / PROFES_FULL()")
print("  3) main: main/FULL_DEOBFUSCATED.lua")
print("======================================================")
notify("Script-Profes", "Ready! " .. S.dir)
