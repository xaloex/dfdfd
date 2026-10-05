--[[═════════════════════════════════════════════════════════════════════════
    LURAPH v15 DUMPER / UNPACKER  —  v2

    ПОЧЕМУ В ПРЕДЫДУЩЕЙ ВЕРСИИ НИЧЕГО НЕ ДЕКОМПИЛИРОВАЛОСЬ (7 реальных багов):
      1) hookmetamethod(game,"__namecall", newcclosure(function() ... oldNC ... end))
         Внутри newcclosure НЕТ upvalues, поэтому oldNC = nil -> хук HttpGet
         падал при ЛЮБОМ вызове. (Это главная причина «пустых» дампов.)
      2) Логирование FireServer висело на __namecall у game, а remote:FireServer()
         идёт через __index САМОГО инстанса -> 0 срабатываний.
      3) request() возвращает (success, code, body, headers), а проверка была
         type(results[1])=="table" -> условие никогда не выполнялось.
      4) checkcaller() == true для любого скрипта из эксплоита -> HttpGet пропускался.
      5) loadstring не был в pcall -> ошибка компиляции роняла хук, исходник терялся.
      6) НЕ БЫЛО хука на load() — а именно его вызывает VM Luraph v15.
      7) НЕ было обработки бинарника: Luraph v15 скармливает load() БАЙТКОД,
         а не текст, поэтому текстовых дампов не появлялось вообще.

    ЧТО СТАЛО:
      • Хуки loadstring / load / request / http_request / syn.request / setfenv / getfenv
      • Хук HttpService:RequestAsync/Request/GetAsync + легаси game:HttpGet*/HttpPost*
      • Хук Remote*: __namecall ставится ОДИН РАЗ НА КЛАСС (в Roblox metatable
        общий на класс) — иначе хуки цепляются друг за друга -> рекурсия
      • Каждый перехваченный chunk сортируется автоматически:
          текст         -> scripts/NNN_*.lua
          байткод       -> scripts/NNN_*.chunk.bin + .chunk.b64.txt
          string.dump   -> scripts/NNN_*.dump.bin  + .dump.b64.txt
          ECR-контейнер -> scripts/NNN_*.ecr.lua   (авто-расшифровка)
      • Строки из байткода -> *_bc_strings.txt (EOR не мешает: строки хранятся
        байт-реверсом, при котором ASCII остаётся ASCII)
      • Обход getprotos/getconstants/getupvalues по всем замыканиям
      • dumper.log + 00_STATUS.txt: видно, какой хук встал, а какой нет

    ПОРЯДОК ЗАПУСКА:
      1) Запусти ЭТОТ файл.
      2) ПОТОМ запускай свой обфусцированный Luraph v15 скрипт.
      3) Файлы появятся в workspace/ScriptDumps/<дата_время>/
══════════════════════════════════════════════════════════════════════════]]

---------------------------------------------------------------------------
-- 0. СОСТОЯНИЕ
---------------------------------------------------------------------------
local okGenv, genv = pcall(function()
	if type(getgenv) == "function" then return getgenv() end
	return _G
end)
if not okGenv or type(genv) ~= "table" then genv = _G end

local STATE_KEY = "__LURAPH_DUMPER_STATE"

local function stateRef()
	local ok, v = pcall(rawget, _G, STATE_KEY)
	if type(v) == "table" then return v end
	ok, v = pcall(rawget, genv, STATE_KEY)
	if type(v) == "table" then return v end
	return nil
end

local prevState = stateRef()
if type(prevState) == "table" and prevState.active then
	print("[Dumper] Already running. Use DUMPER_RETRY() to re-hook")
	return
end

local userCfgRaw = rawget(genv, "LURAPH_DUMPER_CFG")
if type(userCfgRaw) ~= "table" then userCfgRaw = {} end
local userCfg = userCfgRaw

local S = {
	active = true,
	selfMarker = STATE_KEY,
	dir = nil,
	cfg = {
		native = userCfg.native ~= false,           -- newcclosure, если он безопасен
		skipSelf = userCfg.skipSelf ~= false,
		walkProtos = userCfg.walkProtos ~= false,
		hookRemotes = userCfg.hookRemotes ~= false,
		maxRemotes = userCfg.maxRemotes or 200,
		maxFunctions = userCfg.maxFunctions or 60000,
		maxStrings = userCfg.maxStrings or 300000,
		stringsFromBytecode = userCfg.stringsFromBytecode ~= false,
		ecr = userCfg.ecr ~= false,
		verbose = userCfg.verbose ~= false,
	},
	counter = 0,
	httpCount = 0,
	seen = {},
	allText = {},
	strings = {},
	urls = {},
	remoteLog = {},
	remoteTotal = 0,
	cap = {},
	remHooked = {},
	remBase = {},
	prev = {},
	logBuf = {},
	treeBuf = {},
	flushed = {},
	walkCount = 0,
	stringCount = 0,
	dupes = 0,
	probeCaptured = false,
}
rawset(genv, STATE_KEY, S)
if _G and _G ~= genv then pcall(rawset, _G, STATE_KEY, S) end

---------------------------------------------------------------------------
-- 1. ФАЙЛОВАЯ СИСТЕМА
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
	if not S.hasWrite then return end
	local cur = ""
	for piece in relDir:gmatch("[^/]+") do
		cur = (cur == "") and piece or (cur .. "/" .. piece)
		makeDir(S.dir .. "/" .. cur)
	end
end

function S.log(msg)
	local line = string.format("[%s] %s", os.date("%H:%M:%S"), tostring(msg))
	table.insert(S.logBuf, line)
	if #S.logBuf > 800 then table.remove(S.logBuf, 1) end
	if S.cfg.verbose then print("[Dumper] " .. tostring(msg)) end
	if S.hasWrite and S.dir then
		pcall(writefile, S.dir .. "/dumper.log", table.concat(S.logBuf, "\n"))
	end
end

function S.save(relPath, content)
	if not S.hasWrite then return false end
	local dirPart = relPath:match("^(.*)[/][^/]*$")
	if dirPart and dirPart ~= "" then ensureRelDir(dirPart) end
	local ok, err = pcall(writefile, S.dir .. "/" .. relPath, content)
	if not ok then S.log("WRITE FAIL " .. relPath .. ": " .. tostring(err)) end
	return (ok and true) or false
end

-- запись бинарника БЕЗ tostring(), иначе портится байткод
function S.saveRaw(relPath, data)
	if not S.hasWrite then return false end
	local dirPart = relPath:match("^(.*)[/][^/]*$")
	if dirPart and dirPart ~= "" then ensureRelDir(dirPart) end
	local ok, err = pcall(writefile, S.dir .. "/" .. relPath, data)
	if not ok then S.log("WRITE FAIL(raw) " .. relPath .. ": " .. tostring(err)) end
	return (ok and true) or false
end

local ROOT_DIR = "ScriptDumps"
makeDir(ROOT_DIR)
S.dir = ROOT_DIR .. "/" .. os.date("%Y-%m-%d_%H-%M-%S")
makeDir(S.dir)
S.log("Session: workspace/" .. S.dir)

if not S.hasWrite then
	print("[Dumper] WARNING: no writefile in this executor - NOWHERE TO SAVE")
	S.log("writefile missing -> dumps are NOT saved to disk")
end

---------------------------------------------------------------------------
-- 2. УТИЛИТЫ
---------------------------------------------------------------------------
local function hashStr(s)
	local h = 5381
	local n = #s
	local step = (n > 8192) and math.floor(n / 8192) or 1
	for i = 1, n, step do
		h = (h * 33 + s:byte(i)) % 4294967296
	end
	return string.format("%08x_%d", h, n)
end

local function isBinary(s)
	if s:find("\0", 1, true) then return true end
	if s:sub(1, 1) == "\27" then return true end
	return false
end

local function b64encode(data)
	local n = #data
	local blocks = {}
	local buf = {}
	local bufLen = 0
	local i = 1
	while i <= n do
		local a, b, c = data:byte(i, i + 2)
		local v = a * 65536 + (b or 0) * 256 + (c or 0)
		local seq = {
			math.floor(v / 262144),
			math.floor(v / 4096) % 64,
			math.floor(v / 64) % 64,
			v % 64,
		}
		local q1, q2, q3, q4 = seq[1], seq[2], seq[3], seq[4]
		buf[#buf + 1] = string.char(
			(q1 < 26 and 65 + q1) or (q1 < 52 and 71 + q1 - 26) or (q1 < 62 and 48 + q1 - 52) or (q1 == 62 and 43) or 47,
			(q2 < 26 and 65 + q2) or (q2 < 52 and 71 + q2 - 26) or (q2 < 62 and 48 + q2 - 52) or (q2 == 62 and 43) or 47,
			(q3 < 26 and 65 + q3) or (q3 < 52 and 71 + q3 - 26) or (q3 < 62 and 48 + q3 - 52) or (q3 == 62 and 43) or 47,
			(q4 < 26 and 65 + q4) or (q4 < 52 and 71 + q4 - 26) or (q4 < 62 and 48 + q4 - 52) or (q4 == 62 and 43) or 47
		)
		bufLen = bufLen + 1
		if bufLen >= 1024 then
			blocks[#blocks + 1] = table.concat(buf)
			buf = {}
			bufLen = 0
		end
		i = i + 3
	end
	if bufLen > 0 then blocks[#blocks + 1] = table.concat(buf) end
	local res = table.concat(blocks)
	local rem = n % 3
	if rem == 1 then res = res:sub(1, #res - 2) .. "=="
	elseif rem == 2 then res = res:sub(1, #res - 1) .. "=" end
	return res
end

local function hexDump(s, maxBytes)
	maxBytes = maxBytes or 192
	local parts = {}
	for i = 1, math.min(#s, maxBytes) do
		parts[#parts + 1] = string.format("%02X", s:byte(i))
	end
	return table.concat(parts, " ")
end

-- быстрое вытаскивание печатных прогонов (с лимитом, иначе 1.9 MB байткода
-- съедает память и секунды CPU)
function S.extractPrintable(s, minLen, maxRuns)
	minLen = minLen or 5
	maxRuns = maxRuns or 20000
	local out = {}
	local n = #s
	local i = 1
	local truncated = false
	while i <= n do
		local st, en = s:find("[\32-\126]+", i)
		if not st then break end
		if en - st + 1 >= minLen then
			if #out >= maxRuns then
				truncated = true
				break
			end
			out[#out + 1] = s:sub(st, en)
		end
		i = en + 1
	end
	if truncated then out[#out + 1] = "<< обрезано, прогонов больше " .. tostring(maxRuns) .. " >>" end
	return out
end

local function notify(title, text)
	pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification", {
			Title = title, Text = text, Duration = 5
		})
	end)
end

-- ###########################################################################
-- КРИТИЧНО: newcclosure в Luau НЕ ДАЁТ доступа к upvalues.
-- Поэтому сначала проверяем это РUNTIME-тестом, и если upvalues не выживают,
-- нативную обёртку НЕ используем (иначе получим nil вместо orig-функции).
local function nativeKeepsUpvalues()
	if type(newcclosure) ~= "function" then return false, "нет newcclosure" end
	local marker = {}
	local function probe() return marker end
	local ok, res = pcall(function()
		return newcclosure(probe)() == marker
	end)
	if not ok then return false, "newcclosure бросает на upvalue" end
	if res ~= true then return false, "newcclosure обнуляет upvalue" end
	return true, "upvalue сохраняются"
end

local nativeOk, nativeInfo = nativeKeepsUpvalues()
S.cap = S.cap or {}
S.cap.nativeProbe = nativeInfo
if not nativeOk then
	-- проба не прошла -> нативные обёртки гарантированно сломаны (upvalue=nil)
	S.cfg.native = false
	S.cap.nativeForced = "native выключен автоматически: " .. tostring(nativeInfo)
elseif userCfg.native == false then
	S.cap.nativeForced = "native выключен вручную в LURAPH_DUMPER_CFG"
end

-- Обёртка нативной делается ТОЛЬКО если это безопасно; маркеры нужны, чтобы
-- повторная установка (DUMPER_RETRY) не оборачивала нашу же обёртку.
-- ВАЖНО: маркеры вешаем обычным присваиванием, а НЕ через rawset —
-- rawset/rawget требуют таблицу, а тут функции (иначе ошибка
-- "invalid argument #1 to 'rawget' (table expected, got function)").
local function tagHook(fn, base)
	if type(fn) ~= "function" then return fn end
	pcall(function() fn.__dumperHook = true end)
	pcall(function() fn.__dumperBase = base or fn end)
	return fn
end

local function isOurHook(fn)
	if type(fn) ~= "function" then return false end
	local ok, v = pcall(function() return fn.__dumperHook end)
	return (ok and v == true) or false
end

local function hookBaseOf(fn)
	if type(fn) ~= "function" then return nil end
	local ok, v = pcall(function() return fn.__dumperBase end)
	if ok and type(v) == "function" then return v end
	return nil
end

local function baseOf(prev)
	if type(prev) ~= "function" then return prev end
	if isOurHook(prev) then
		local b = hookBaseOf(prev)
		if type(b) == "function" then return b end
	end
	return prev
end

local function makeNative(fn)
	if not S.cfg.native then return fn end
	if type(newcclosure) ~= "function" then return fn end
	local ok, res = pcall(newcclosure, fn)
	if ok and type(res) == "function" then return tagHook(res, fn) end
	return fn
end

---------------------------------------------------------------------------
-- 3. ECR-РАСШИФРОВКА (контейнер "\27LUA" + байт-ключ + EOR-поток)
---------------------------------------------------------------------------
local function decodeEor(data, key, startIdx, variant)
	local n = #data
	if n < startIdx + 8 then return nil end
	local out = {}
	local prev = key
	for i = startIdx, n do
		local b = data:byte(i)
		local v
		if i == startIdx and variant == 2 then
			v = prev
		else
			v = (b + prev) % 256
			prev = v
		end
		out[#out + 1] = string.char(v)
	end
	return table.concat(out)
end

local function ecrScore(d)
	if #d < 8 then return -999 end
	local score = 0
	-- байт версии Luau + 5 байт типов должны быть маленькими числами
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
	score = score + (printable / sample) * 6
	return score
end

function S.tryEcrDecode(data)
	if not S.cfg.ecr then return nil end
	if #data < 40 then return nil end
	if data:sub(1, 4) ~= "\27LUA" then return nil end   -- только ECR-контейнеры

	-- ключ подбираем на первых 4 KB, полный декод делаем один раз
	local head = data:sub(1, 4096)
	local keys = {0x5D, 0x5B, 0x5C, 0x5E, 0x09, 0x2A, 0x11, 0x37, 0x00, 0xFF,
		data:byte(4), data:byte(5), data:byte(6)}
	local bestScore, bKey, bStart, bVariant = -math.huge, nil, nil, nil
	for ki = 1, #keys do
		local key = keys[ki]
		for startIdx = 5, 6 do
			for variant = 1, 2 do
				local d = decodeEor(head, key, startIdx, variant)
				if d then
					local sc = ecrScore(d)
					if sc > bestScore then bestScore, bKey, bStart, bVariant = sc, key, startIdx, variant end
				end
			end
		end
	end
	if bestScore < 11 or not bKey then return nil end

	local full = decodeEor(data, bKey, bStart, bVariant)
	if not full then return nil end
	S.lastEcr = string.format("key=0x%02X start=%d variant=%d score=%.1f", bKey, bStart, bVariant, bestScore)
	return full, S.lastEcr
end

---------------------------------------------------------------------------
-- 4. РАЗБОР ПЕРЕХВАЧЕННОГО CHUNK-А
---------------------------------------------------------------------------
function S.inspectBytecode(base, dumped, n, tag)
	local suffix = "_" .. tostring(tag)
	S.save(base .. suffix .. "_head.txt", string.format(
		"#%d tag=%s len=%d\nHEX[0..191]:\n%s\n\nPRINTABLE RUNS:\n%s",
		n, tag, #dumped, hexDump(dumped, 192),
		table.concat(S.extractPrintable(dumped, 5, 4000), "\n")))

	if S.cfg.stringsFromBytecode then
		local runs = S.extractPrintable(dumped, 6, 60000)
		if #runs > 0 then S.save(base .. suffix .. "_bc_strings.txt", table.concat(runs, "\n")) end
	end

	local dec, info = S.tryEcrDecode(dumped)
	if dec then S.save(base .. suffix .. "_ecr.lua", "-- ECR auto-decoded: " .. tostring(info) .. "\n" .. dec) end
end

function S.onChunk(src, chunkname, tag, ok, compiled)
	if type(src) == "function" then
		local dOk, dumped = pcall(string.dump, src)
		if dOk and type(dumped) == "string" then
			S.counter = S.counter + 1
			local n = S.counter
			local h = hashStr(dumped)
			if S.seen[h] then
				S.dupes = S.dupes + 1
			else
				S.seen[h] = true
				S.saveRaw(string.format("scripts/%03d_%s_fn_%s.dump.bin", n, tag, h), dumped)
			end
		end
		return
	end

	if type(src) ~= "string" or #src < 2 then return end

	if src:find("__DUMPER_PROBE__", 1, true) then
		S.probeCaptured = true
		return
	end
	if S.cfg.skipSelf and src:find(S.selfMarker, 1, true) then return end

	S.counter = S.counter + 1
	local n = S.counter
	local h = hashStr(src)
	if S.seen[h] then
		S.dupes = S.dupes + 1
		S.log(string.format("dup #%d (%s) skipped, len=%d", n, tag, #src))
		return
	end
	S.seen[h] = true

	local base = string.format("scripts/%03d_%s_%s", n, tag, h)
	local hdr = table.concat({
		"-- ==== ScriptDumper v2 ====",
		"-- #" .. n .. "  tag=" .. tag,
		"-- chunkname: " .. tostring(chunkname),
		"-- length: " .. #src .. " bytes",
		"-- date: " .. os.date("%Y-%m-%d %H:%M:%S"),
		"---------------------------------------------",
		"",
		"",
	}, "\n")

	if isBinary(src) then
		S.log(string.format("#%d %s BINARY chunk (%d bytes) -> .chunk.bin", n, tag, #src))
		S.saveRaw(base .. ".chunk.bin", src)
		S.save(base .. ".chunk.b64.txt", b64encode(src))
		S.save(base .. ".chunk.info.txt", string.format(
			"-- original bytes passed to %s(%s)\n-- length: %d\n-- isECR: %s\n-- HEX[0..63]:\n%s\n",
			tag, tostring(chunkname), #src,
			tostring(src:sub(1, 4) == "\27LUA"), hexDump(src, 64)))

		local dec, info = S.tryEcrDecode(src)
		if dec then
			S.saveRaw(base .. ".ecr.bin", dec)
			S.save(base .. ".ecr.b64.txt", b64encode(dec))
			S.save(base .. ".ecr.lua", "-- ECR auto-decoded: " .. tostring(info) .. "\n" .. dec)
			S.log("#" .. n .. " ECR decoded: " .. tostring(info))
		end
		S.inspectBytecode(base, src, n, tag .. "_chunk")
	else
		S.save(base .. ".lua", hdr .. src)
		table.insert(S.allText, string.format("\n\n-- ==== #%d tag=%s chunk=%s len=%d ====\n%s",
			n, tag, tostring(chunkname), #src, src))
		S.log(string.format("#%d %s TEXT (%d chars) -> %s.lua", n, tag, #src, base))
		-- ищем глобалы, которых нет в окружении -> "attempt to call a nil value"
		if #src <= 4000000 then
			local okRep, errRep = pcall(S.reportGlobals, src, n)
			if not okRep then S.log("reportGlobals error: " .. tostring(errRep)) end
		end
		notify("Dumper", string.format("#%d текст %d KB", n, math.floor(#src / 1024)))
	end

	-- string.dump скомпилированной функции — чистый байткод Luau для unluau
	if ok and type(compiled) == "function" and type(string.dump) == "function" then
		local dOk, dumped = pcall(string.dump, compiled)
		if dOk and type(dumped) == "string" and #dumped > 0 then
			S.saveRaw(base .. ".dump.bin", dumped)
			S.save(base .. ".dump.b64.txt", b64encode(dumped))
			S.inspectBytecode(base, dumped, n, tag .. "_dump")
		end
	end

	-- обход замыканий самый тяжёлый этап (десятки тысяч getprotos/getconstants),
	-- поэтому в отдельный поток, чтобы не подвешивать игру внутри load()
	if S.cfg.walkProtos and ok and type(compiled) == "function" then
		local job = function() pcall(S.walkFn, compiled, base, 0) end
		if type(task) == "table" and type(task.spawn) == "function" then
			task.spawn(job)
		else
			job()
		end
	end

	S.flushRecon()
end

---------------------------------------------------------------------------
-- 5. ОБХОД ЗАМЫКАНИЙ (getprotos / getconstants / getupvalues)
---------------------------------------------------------------------------
function S.walkFn(fn, base, depth)
	if type(fn) ~= "function" then return end
	if depth > 10 then return end
	if S.walkCount > S.cfg.maxFunctions then return end
	S.walkVisited = S.walkVisited or {}
	if S.walkVisited[fn] then return end
	S.walkVisited[fn] = true
	S.walkCount = S.walkCount + 1

	local lines = S.treeBuf
	local pad = string.rep("  ", depth)

	local info = {}
	if type(debug) == "table" and type(debug.getinfo) == "function" then
		pcall(function() info = debug.getinfo(fn) or {} end)
	end

	table.insert(lines, string.format("%sfn [%s] L%s..%s params=%s vararg=%s",
		pad, tostring(info.short_src or "?"):sub(1, 46),
		tostring(info.linedefined or "?"), tostring(info.lastlinedefined or "?"),
		tostring(info.nparams or "?"), tostring(info.isvararg)))

	local getconst = rawget(genv, "getconstants") or rawget(_G, "getconstants")
	if type(getconst) == "function" then
		local cOk, consts = pcall(getconst, fn)
		if cOk and type(consts) == "table" then
			local sample, cnt = {}, 0
			for _, c in pairs(consts) do
				if type(c) == "string" then
					cnt = cnt + 1
					local cleaned = c:gsub("[%c]", " ")
					if S.stringCount < S.cfg.maxStrings then
						table.insert(S.strings, cleaned)
						S.stringCount = S.stringCount + 1
						if cleaned:find("http", 1, true)
							or cleaned:find("pastebin", 1, true)
							or cleaned:find("github", 1, true)
							or cleaned:find("roblox", 1, true)
							or cleaned:find("webhook", 1, true) then
							table.insert(S.urls, cleaned)
						end
					end
					if #sample < 24 then table.insert(sample, string.format("%q", cleaned:sub(1, 48))) end
				elseif type(c) == "number" or type(c) == "boolean" then
					if #sample < 24 then table.insert(sample, tostring(c)) end
				end
			end
			table.insert(lines, string.format("%s  consts(%d): %s", pad, cnt, table.concat(sample, ", ")))
		end
	end

	local getupval = rawget(genv, "getupvalues") or rawget(_G, "getupvalues")
	if type(getupval) == "function" then
		local uOk, uvs = pcall(getupval, fn)
		if uOk and type(uvs) == "table" then
			local names = {}
			for k, uv in pairs(uvs) do
				if type(uv) == "string" then
					if S.stringCount < S.cfg.maxStrings then
						table.insert(S.strings, uv)
						S.stringCount = S.stringCount + 1
					end
				elseif type(uv) == "function" then
					if #names < 20 then names[#names + 1] = "fn" end
					pcall(S.walkFn, uv, base, depth + 1)
				elseif #names < 20 then
					local vs = tostring(uv)
					names[#names + 1] = tostring(k) .. "=" .. vs:sub(1, 24)
				end
			end
			table.insert(lines, string.format("%s  upvals(%d): %s", pad, #uvs, table.concat(names, ", ")))
		end
	end

	local getprotos = rawget(genv, "getprotos") or rawget(_G, "getprotos")
	if type(getprotos) == "function" then
		local pOk, protos = pcall(getprotos, fn)
		if pOk and type(protos) == "table" then
			local list = {}
			for k, v in pairs(protos) do
				if type(v) == "function" then table.insert(list, { k = k or 0, f = v }) end
			end
			table.sort(list, function(a, b) return a.k < b.k end)
			table.insert(lines, string.format("%s  protos: %d", pad, #list))
			for _, item in ipairs(list) do
				pcall(S.walkFn, item.f, base, depth + 1)
			end
		end
	end

	if #lines > 400 then
		S.save(base .. "_closure_tree.txt", table.concat(lines, "\n"))
		S.log("closure tree truncated at " .. #lines .. " lines")
		-- чистим IN PLACE, иначе родители продолжат писать в отсоединённую таблицу
		for i = #lines, 1, -1 do lines[i] = nil end
	end
end

-- flush не на каждый chunk (иначе _ALL_SOURCE.lua переписывается десятки раз),
-- а при заметном росте; форс — из DUMPER_FLUSH()
function S.flushRecon(force)
	force = force and true or false
	if #S.treeBuf > 0 then
		S.save("closure_tree_partial.txt", table.concat(S.treeBuf, "\n"))
	end
	if #S.strings > 0 then
		local last = S.flushed.strings or 0
		if force or (#S.strings - last) >= 2000 or last == 0 then
			S.save("luraph_strings.txt", table.concat(S.strings, "\n"))
			S.flushed.strings = #S.strings
		end
	end
	if #S.urls > 0 and (force or #S.urls ~= (S.flushed.urls or 0)) then
		S.save("luraph_urls.txt", table.concat(S.urls, "\n"))
		S.flushed.urls = #S.urls
	end
	if #S.allText > 0 then
		local last = S.flushed.all or 0
		if force or (#S.allText - last) >= 1 then
			S.save("_ALL_SOURCE.lua", table.concat(S.allText, "\n"))
			S.flushed.all = #S.allText
		end
	end
end

---------------------------------------------------------------------------
-- 6. ХУКИ КОМПИЛЯЦИИ (loadstring / load)
---------------------------------------------------------------------------
local hookCount = 0

local function buildChunkHook(origCompile, tag)
	local wrapper = function(...)
		local packed = table.pack(...)
		local ok, a, b, c = pcall(origCompile, table.unpack(packed, 1, packed.n))
		local Sx = stateRef()
		if type(Sx) == "table" and type(Sx.onChunk) == "function" then
			pcall(Sx.onChunk, packed[1], packed[2], tag, ok, a)
		end
		if not ok then error(a, 0) end
		return a, b, c
	end
	return tagHook(makeNative(wrapper), origCompile)
end

local function install(name, tag)
	local orig = rawget(genv, name) or rawget(_G, name)
	if type(orig) ~= "function" then return false, "нет функции" end
	if isOurHook(orig) then return true, "уже наш хук" end
	local wrapped = buildChunkHook(orig, tag)
	local ok1 = pcall(function() rawset(genv, name, wrapped) end)
	local ok2 = pcall(function() rawset(_G, name, wrapped) end)
	local sharedTbl = rawget(genv, "shared")
	if type(sharedTbl) == "table" and type(rawget(sharedTbl, name)) == "function" then
		pcall(function() rawset(sharedTbl, name, wrapped) end)
	end
	if ok1 or ok2 then
		hookCount = hookCount + 1
		S.log(string.format("hook %s installed (native=%s)", name, tostring(S.cfg.native)))
		return true, "ok"
	end
	S.log("hook " .. name .. " NOT installed (read-only)")
	return false, "read-only"
end

---------------------------------------------------------------------------
-- 7. ХУКИ HTTP (game:HttpGet* + HttpService:RequestAsync)
---------------------------------------------------------------------------
function S.saveHttp(url, body, method)
	if type(body) ~= "string" or #body == 0 then return end
	S.httpCount = S.httpCount + 1
	local n = S.httpCount
	local h = hashStr(body)
	if S.seen["http_" .. h] then return end
	S.seen["http_" .. h] = true

	local safeUrl = tostring(url or "?"):gsub("[^%w]", "_"):sub(1, 60)
	local base = string.format("http/%03d_%s_%s", n, safeUrl, h)
	S.save(base .. ".body", "-- URL: " .. tostring(url) .. "\n-- via: " .. tostring(method)
		.. "\n-- Size: " .. #body .. "\n\n" .. body)
	S.save(base .. ".url.txt", tostring(url))
	S.log(string.format("HTTP #%d %s %s (%d bytes)", n, tostring(method), tostring(url), #body))
	notify("Dumper", "HTTP #" .. n .. " " .. tostring(method) .. " " .. tostring(url):sub(1, 34))
end

local function patchHttpService()
	if type(hookmetamethod) ~= "function" then
		S.log("no hookmetamethod -> HTTP not hooked")
		return false
	end
	local okSvc, svc = pcall(function() return game:GetService("HttpService") end)
	if not okSvc or type(svc) ~= "instance" then
		S.log("HttpService unavailable")
		return false
	end

	local namecall = function(self, ...)
		local method = getnamecallmethod()
		if method == "RequestAsync" or method == "Request"
			or method == "GetAsync" or method == "Get" then
			local first = select(1, ...)
			local url = "?"
			if type(first) == "table" then url = first.Url or first.URL or "?"
			elseif type(first) == "string" then url = first end
			local base = S.prev.httpNC
			if type(base) ~= "function" then return end
			local res = table.pack(base(self, ...))
			pcall(S.saveHttp, url, type(res[1]) == "string" and res[1] or nil, method)
			return table.unpack(res, 1, res.n)
		end
		local base = S.prev.httpNC
		if type(base) == "function" then return base(self, ...) end
	end
	local native = makeNative(namecall)
	local ok1, prev = pcall(hookmetamethod, svc, "__namecall", native)
	if ok1 and type(prev) == "function" then
		-- prev может быть НАШИМ же хуком (повторная установка) -> берём оригинал
		local base = baseOf(prev)
		if type(base) == "function" then S.prev.httpNC = base end
		tagHook(native, S.prev.httpNC)
		S.log("hook HttpService:RequestAsync/GetAsync installed")
		hookCount = hookCount + 1
		return true
	end
	S.log("hook HttpService NOT installed: " .. tostring(prev))
	return false
end

local function patchGame()
	if type(hookmetamethod) ~= "function" then
		S.log("no hookmetamethod -> game:* not hooked")
		return false
	end
	local namecall = function(self, ...)
		local method = getnamecallmethod()
		if method == "HttpGet" or method == "HttpGetAsync"
			or method == "HttpPost" or method == "HttpPostAsync" then
			local url = select(1, ...)
			local base = S.prev.gameNC
			if type(base) ~= "function" then return end
			local res = table.pack(base(self, ...))
			pcall(S.saveHttp, tostring(url), type(res[1]) == "string" and res[1] or nil, method)
			return table.unpack(res, 1, res.n)
		end
		local base = S.prev.gameNC
		if type(base) == "function" then return base(self, ...) end
	end
	local native = makeNative(namecall)
	local ok1, prev = pcall(hookmetamethod, game, "__namecall", native)
	if ok1 and type(prev) == "function" then
		local base = baseOf(prev)
		if type(base) == "function" then S.prev.gameNC = base end
		tagHook(native, S.prev.gameNC)
		S.log("hook game:HttpGet*/HttpPost* installed")
		hookCount = hookCount + 1
		return true
	end
	S.log("hook game NOT installed: " .. tostring(prev))
	return false
end

---------------------------------------------------------------------------
-- 8. ХУКИ request / http_request / syn.request
---------------------------------------------------------------------------
local function extractBody(res)
	local body
	for i = 1, res.n do
		local v = res[i]
		if type(v) == "string" and #v > 0 then
			if not body or #v > #body then body = v end
		elseif type(v) == "table" then
			local b = v.Body or v.body or v.Text
			if type(b) == "string" and #b > 0 then
				if not body or #b > #body then body = b end
			end
		end
	end
	return body
end

local function installRequest(name, holder)
	local orig = rawget(holder, name)
	if type(orig) ~= "function" then return false end
	if isOurHook(orig) then return true end
	local wrapper = function(...)
		local res = table.pack(orig(...))
		local opts = select(1, ...)
		local url, reqBody
		if type(opts) == "table" then
			url = opts.Url or opts.URL
			if type(opts.Body) == "string" then reqBody = opts.Body end
		end
		pcall(S.saveHttp, tostring(url), extractBody(res), name)
		if reqBody then
			S.httpCount = S.httpCount + 1
			S.save(string.format("http/post_%03d.txt", S.httpCount),
				"-- POST to " .. tostring(url) .. "\n\n" .. reqBody)
		end
		return table.unpack(res, 1, res.n)
	end
	tagHook(wrapper, orig)
	local ok = pcall(function() rawset(holder, name, makeNative(wrapper)) end)
	if ok then
		S.log("hook " .. name .. " installed")
		hookCount = hookCount + 1
	end
	return ok
end

---------------------------------------------------------------------------
-- 9. ХУКИ setfenv / getfenv + пропатч env-таблиц
---------------------------------------------------------------------------
function S.patchEnv(env)
	if type(env) ~= "table" then return end
	for _, name in ipairs({"loadstring", "load"}) do
		local cur = rawget(env, name)
		if type(cur) == "function" and not isOurHook(cur) then
			local wrapped = buildChunkHook(cur, name .. "_env")
			if pcall(rawset, env, name, wrapped) then
				S.log("env table patched: " .. name)
			end
		end
	end
end

local function installEnvHooks()
	local origSet = rawget(genv, "setfenv")
	if type(origSet) == "function" and not isOurHook(origSet) then
		local wrapper = function(f, env)
			if type(env) == "table" then pcall(S.patchEnv, env) end
			return origSet(f, env)
		end
		tagHook(wrapper, origSet)
		if pcall(function() rawset(genv, "setfenv", makeNative(wrapper)) end) then
			S.log("hook setfenv installed")
			hookCount = hookCount + 1
		end
	end

	local origGet = rawget(genv, "getfenv")
	if type(origGet) == "function" and not isOurHook(origGet) then
		local wrapper = function(f)
			local env = origGet(f)
			if type(env) == "table" then pcall(S.patchEnv, env) end
			return env
		end
		tagHook(wrapper, origGet)
		if pcall(function() rawset(genv, "getfenv", makeNative(wrapper)) end) then
			S.log("hook getfenv installed")
			hookCount = hookCount + 1
		end
	end
end

---------------------------------------------------------------------------
-- 10. ХУКИ REMOTE-СОБЫТИЙ
-- ВАЖНО: в Roblox metatable общий на КЛАСС, поэтому hookmetamethod(inst, ...)
-- вешает хук на ВСЕ инстансы этого класса. Ставим один хук на класс, иначе
-- новый hookmetamethod вернёт предыдущий НАШ хук -> бесконечная рекурсия.
---------------------------------------------------------------------------
local REMOTE_METHODS = {
	FireServer = true, FireClient = true, InvokeServer = true,
	InvokeClient = true, FireAllClients = true,
}
local REMOTE_CLASSES = {
	RemoteEvent = true, RemoteFunction = true, UnreliableRemoteEvent = true,
	BindableEvent = true, ClickDetector = true,
}

function S.hookRemote(inst)
	if type(inst) ~= "instance" then return false end
	if type(hookmetamethod) ~= "function" then return false end
	if type(getnamecallmethod) ~= "function" then return false end
	local cn = inst.ClassName
	if S.remHooked[cn] then return true end
	S.remHooked[cn] = true

	local hook = function(self, ...)
		local method = getnamecallmethod()
		if REMOTE_METHODS[method] then
			local args = table.pack(...)
			pcall(S.logRemote, self, method, args)
		end
		local base = S.remBase[cn]
		if type(base) == "function" then return base(self, ...) end
		return ...
	end
	tagHook(hook)

	local ok, prev = pcall(hookmetamethod, inst, "__namecall", makeNative(hook))
	if ok and type(prev) == "function" then
		S.remBase[cn] = baseOf(prev)
		return true
	end
	S.remHooked[cn] = nil
	return false
end

function S.logRemote(inst, method, args)
	S.remoteTotal = S.remoteTotal + 1
	local fullName = "?"
	pcall(function() fullName = inst:GetFullName() end)
	local parts = {}
	for i = 1, math.min(args.n, 12) do
		local v = args[i]
		local t = type(v)
		if t == "string" then
			parts[#parts + 1] = string.format("%q", v:sub(1, 60))
		elseif t == "number" or t == "boolean" then
			parts[#parts + 1] = tostring(v)
		elseif t == "nil" then
			parts[#parts + 1] = "nil"
		else
			parts[#parts + 1] = "<" .. t .. ">"
		end
	end
	local line = string.format("[%s] %s:%s(%s)",
		os.date("%H:%M:%S"), fullName, method, table.concat(parts, ", "))
	table.insert(S.remoteLog, line)
	if #S.remoteLog > 4000 then table.remove(S.remoteLog, 1) end
	S.save("remotes_log.txt", table.concat(S.remoteLog, "\n"))
end

function S.scanRemotes()
	if not S.cfg.hookRemotes then return end
	local n = 0
	local ok, list = pcall(function() return game:GetDescendants() end)
	if ok and type(list) == "table" then
		for _, inst in ipairs(list) do
			if REMOTE_CLASSES[inst.ClassName] then
				if S.hookRemote(inst) then n = n + 1 end
				if n >= S.cfg.maxRemotes then break end
			end
		end
	end
	S.log("remote classes hooked: " .. tostring(n))

	if not S.descConn then
		pcall(function()
			S.descConn = game.DescendantAdded:Connect(function(inst)
				if REMOTE_CLASSES[inst.ClassName] then pcall(S.hookRemote, inst) end
			end)
		end)
	end
end

---------------------------------------------------------------------------
-- 11. СОВМЕСТИМОСТЬ (шимы)
-- Захваченный payload требует bit32 (16 обращений), setfenv, unpack и load.
-- В этом эксплоите их НЕТ -> VM Luraph v15 падает на первой строке
-- (Oq=bit32.band) и payload не выполняется вообще. Ставим шимы ДО payload.
---------------------------------------------------------------------------
local function toU32(x)
	x = tonumber(x) or 0
	return math.floor(x) % 4294967296
end

local function luaBand(a, b)
	local res, bitv = 0, 1
	a, b = toU32(a), toU32(b)
	for _ = 1, 32 do
		if a % 2 == 1 and b % 2 == 1 then res = res + bitv end
		a = (a - a % 2) / 2
		b = (b - b % 2) / 2
		bitv = bitv * 2
	end
	return res
end

local function luaBor(a, b)
	local res, bitv = 0, 1
	a, b = toU32(a), toU32(b)
	for _ = 1, 32 do
		if a % 2 == 1 or b % 2 == 1 then res = res + bitv end
		a = (a - a % 2) / 2
		b = (b - b % 2) / 2
		bitv = bitv * 2
	end
	return res
end

local function luaBxor(a, b)
	local res, bitv = 0, 1
	a, b = toU32(a), toU32(b)
	for _ = 1, 32 do
		if (a % 2) ~= (b % 2) then res = res + bitv end
		a = (a - a % 2) / 2
		b = (b - b % 2) / 2
		bitv = bitv * 2
	end
	return res
end

-- ВАЖНО: нельзя писать x * 2^n напрямую — при x ~ 2^32 и n = 31
-- промежуточное значение ~9.2e18 вылезает за 2^53 и double теряет биты.
-- Поэтому всегда сначала режем по модулю, потом умножаем.
local function luaLshift(x, n)
	n = n % 32
	local u = toU32(x)
	if n == 0 then return u end
	return (u % (2 ^ (32 - n))) * (2 ^ n)
end

local function luaRshift(x, n)
	n = n % 32
	if n == 0 then return toU32(x) end
	return math.floor(toU32(x) / (2 ^ n))
end

local function luaRrotate(x, n)
	n = n % 32
	local u = toU32(x)
	if n == 0 then return u end
	local low = math.floor(u / (2 ^ n))
	local high = (u % (2 ^ n)) * (2 ^ (32 - n))
	return (low + high) % 4294967296
end

local function luaLrotate(x, n)
	n = n % 32
	local u = toU32(x)
	if n == 0 then return u end
	local high = (u % (2 ^ (32 - n))) * (2 ^ n)
	local low = math.floor(u / (2 ^ (32 - n)))
	return (high + low) % 4294967296
end

local function luaArshift(x, n)
	n = n % 32
	local u = toU32(x)
	local s = (u >= 2147483648) and (u - 4294967296) or u
	local r = (n == 0) and s or math.floor(s / (2 ^ n))
	if r >= 2147483648 then return r - 4294967296 end
	return r
end

local function luaExtract(n, field, width)
	field = field % 32
	width = width % 32
	if width == 0 then return 0 end
	return math.floor(toU32(n) / (2 ^ field)) % (2 ^ width)
end

local function luaReplace(n, v, field, width)
	field = field % 32
	width = width % 32
	if width == 0 then return toU32(n) end
	local u = toU32(n)
	local cleared = u - (math.floor(u / (2 ^ field)) % (2 ^ width)) * (2 ^ field)
	return (cleared + (toU32(v) % (2 ^ width)) * (2 ^ field)) % 4294967296
end

local function makeBit32()
	local bitlib = rawget(_G, "bit")
	if type(bitlib) ~= "table" then bitlib = rawget(genv, "bit") end
	local B, origin = {}, "pure-lua"

	local function fast(name)
		return type(bitlib) == "table" and type(bitlib[name]) == "function"
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
		B.band, B.bor, B.bxor = luaBand, luaBor, luaBxor
		B.bnot = function(a) return 4294967295 - toU32(a) end
		B.lshift, B.rshift = luaLshift, luaRshift
		B.rrotate, B.lrotate = luaRrotate, luaLrotate
	end

	B.arshift = luaArshift
	B.extract = luaExtract
	B.replace = luaReplace
	B.len = function() return 32 end
	B.countlz = function(x)
		local u = toU32(x)
		if u == 0 then return 32 end
		local n = 0
		while u < 2147483648 do u = u * 2; n = n + 1 end
		return n
	end
	B.countrz = function(x)
		local u = toU32(x)
		if u == 0 then return 32 end
		local n = 0
		while u % 2 == 0 do u = u / 2; n = n + 1 end
		return n
	end
	return B, origin
end

-- shim ставим сразу во все доступные env-таблицы: скрипт запускается из
-- loadstring и видит глобалы того env, откуда запущен
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

S.shims = {}

local function applyShim(name, value)
	local targets = envTargets()
	local done = false
	for _, t in ipairs(targets) do
		if pcall(rawset, t, name, value) then done = true end
	end
	S.shims[name] = done and "установлен" or "НЕ УСТАНОВЛЕН"
	return done
end

local function installShims()
	-- 1) bit32 (+ countlz/countrz, которых нет даже в bit)
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
		S.shims.bit32 = "дополнен (" .. origin .. "): " .. table.concat(added, ",")
	else
		applyShim("bit32", B)
		S.shims.bit32 = "создан (" .. origin .. ")"
	end
	S.log("shim bit32: " .. tostring(S.shims.bit32))

	-- 2) setfenv — настоящей функции нет, эмулируем через слияние env в глобалы
	if type(rawget(_G, "setfenv")) ~= "function" and type(rawget(genv, "setfenv")) ~= "function" then
		local setfenvShim = function(f, env)
			if type(env) == "table" then
				for k, v in pairs(env) do
					if rawget(_G, k) == nil then pcall(rawset, _G, k, v) end
				end
			end
			local ok, e = pcall(getfenv, 0)
			if ok and type(e) == "table" then return e end
			return env
		end
		applyShim("setfenv", setfenvShim)
		S.log("shim setfenv: created (env merged into _G)")
	else
		S.shims.setfenv = "уже был"
	end

	-- 3) unpack -> table.unpack (в Luau глобального unpack нет)
	if type(rawget(_G, "unpack")) ~= "function" and type(table.unpack) == "function" then
		applyShim("unpack", table.unpack)
		S.log("shim unpack: created (= table.unpack)")
	else
		S.shims.unpack = "уже был"
	end

	-- 4) load -> перехваченный loadstring (иначе VM выполнит payload мимо хука)
	if type(rawget(_G, "load")) ~= "function" and type(rawget(genv, "load")) ~= "function" then
		local loadShim = function(chunk, chunkname, ...)
			local ls = rawget(genv, "loadstring") or rawget(_G, "loadstring")
			if type(ls) == "function" then return ls(chunk, chunkname, ...) end
			return nil, "loadstring недоступен"
		end
		tagHook(loadShim)
		applyShim("load", loadShim)
		S.shims.load = "создан (= перехваченный loadstring)"
		S.log("shim load: created, calls through it are hooked too")
	else
		S.shims.load = "уже был"
	end

	-- 5) getfenv на всякий случай (Luraph его читает)
	if type(rawget(_G, "getfenv")) ~= "function" and type(rawget(genv, "getfenv")) ~= "function" then
		applyShim("getfenv", function(f) return _G end)
		S.log("shim getfenv: created")
	end
end

---------------------------------------------------------------------------
-- 11.7 СТАТИЧЕСКИЙ АНАЛИЗ ГЛОБАЛОВ
-- "attempt to call a nil value" = payload вызывает глобал, которого нет в
-- окружении. Разбираем исходник на токены и выписываем в MISSING_GLOBALS.txt
-- именно те имена, которых реально нет в env.
---------------------------------------------------------------------------
local LUA_KEYWORDS = {
	["and"]=true, ["break"]=true, ["do"]=true, ["else"]=true, ["elseif"]=true,
	["end"]=true, ["false"]=true, ["for"]=true, ["function"]=true, ["if"]=true,
	["in"]=true, ["local"]=true, ["nil"]=true, ["not"]=true, ["or"]=true,
	["repeat"]=true, ["return"]=true, ["then"]=true, ["true"]=true,
	["until"]=true, ["while"]=true, ["continue"]=true, ["export"]=true,
	["goto"]=true,
}

local KNOWN_GLOBALS = {
	-- Luau / Lua
	["_G"]=true, ["_VERSION"]=true, ["assert"]=true, ["error"]=true,
	["getmetatable"]=true, ["setmetatable"]=true, ["rawequal"]=true,
	["rawget"]=true, ["rawlen"]=true, ["rawset"]=true, ["select"]=true,
	["tonumber"]=true, ["tostring"]=true, ["type"]=true, ["typeof"]=true,
	["unpack"]=true, ["print"]=true, ["warn"]=true, ["pcall"]=true,
	["xpcall"]=true, ["newproxy"]=true, ["loadstring"]=true, ["load"]=true,
	["require"]=true, ["coroutine"]=true, ["debug"]=true, ["math"]=true,
	["os"]=true, ["io"]=true, ["string"]=true, ["table"]=true,
	["bit"]=true, ["bit32"]=true, ["utf8"]=true, ["buffer"]=true,
	["task"]=true, ["gcinfo"]=true, ["collectgarbage"]=true, ["tick"]=true,
	["time"]=true, ["delay"]=true, ["spawn"]=true, ["wait"]=true,
	["DateTime"]=true, ["Random"]=true, ["Region3"]=true, ["UDim"]=true, ["UDim2"]=true,
	["Vector2"]=true, ["Vector3"]=true, ["CFrame"]=true, ["Color3"]=true,
	["BrickColor"]=true, ["Instance"]=true, ["Enum"]=true, ["Ray"]=true, ["Rect"]=true,
	["Faces"]=true, ["Axes"]=true, ["PhysicalProperties"]=true,
	["Workspace"]=true, ["Lighting"]=true, ["ReplicatedStorage"]=true,
	["ServerStorage"]=true, ["ServerScriptService"]=true, ["Players"]=true,
	["StarterGui"]=true, ["StarterPack"]=true, ["StarterPlayer"]=true,
	["SoundService"]=true, ["Teams"]=true, ["UserInputService"]=true,
	["RunService"]=true, ["TweenService"]=true, ["ContextActionService"]=true,
	["HttpService"]=true, ["InsertService"]=true, ["GuiService"]=true,
	["MarketplaceService"]=true, ["TeleportService"]=true, ["TextService"]=true,
	["PathfindingService"]=true, ["PhysicsService"]=true, ["CollectionService"]=true,
	["DataStoreService"]=true, ["MessagingService"]=true, ["LocalizationService"]=true,
	["PolicyService"]=true, ["Sound"]=true, ["NumberSequence"]=true,
	["NumberRange"]=true, ["NumberSequenceKeypoint"]=true, ["Font"]=true,
	["Frame"]=true, ["GuiObject"]=true, ["TextLabel"]=true, ["TextButton"]=true,
	["TextBox"]=true, ["ImageLabel"]=true, ["ScrollingFrame"]=true, ["UIGesture"]=true,
	["UIListLayout"]=true, ["UIPadding"]=true, ["UISizeConstraint"]=true,
	["UITextSizeConstraint"]=true, ["UIStroke"]=true, ["UIGradient"]=true,
	["UIAspectRatioConstraint"]=true, ["UICorner"]=true, ["UIPositionConstraint"]=true,
	["Part"]=true, ["WedgePart"]=true, ["MeshPart"]=true, ["TrussPart"]=true,
	["SpawnLocation"]=true, ["Seat"]=true, ["SeatWeld"]=true, ["Weld"]=true,
	["Motor6D"]=true, ["BodyVelocity"]=true, ["BodyAngularVelocity"]=true,
	["BodyPosition"]=true, ["BodyGyro"]=true, ["AlignPosition"]=true,
	["AlignOrientation"]=true, ["Humanoid"]=true, ["HumanoidStateChange"]=true,
	["Animation"]=true, ["AnimationController"]=true, ["Tool"]=true,
	["ClickDetector"]=true, ["ProximityPrompt"]=true, ["RemoteEvent"]=true,
	["RemoteFunction"]=true, ["UnreliableRemoteEvent"]=true, ["BindableEvent"]=true,
	["BindableFunction"]=true, ["PlayerGui"]=true, ["Backpack"]=true,
	["PlayerScripts"]=true, ["PlayerMouse"]=true, ["ContextAction"]=true,
	["LevelOfDetail"]=true, ["NumberPose"]=true, ["Random"]=true,
	-- эксплоиты
	["getgenv"]=true, ["getrenv"]=true, ["getcallingscript"]=true,
	["hookfunction"]=true, ["hookmetamethod"]=true, ["newcclosure"]=true,
	["checkcaller"]=true, ["checknamecall"]=true, ["getnamecallmethod"]=true,
	["setfenv"]=true, ["getfenv"]=true, ["getconstants"]=true, ["getprotos"]=true,
	["getupvalues"]=true, ["getconstant"]=true, ["getupvalue"]=true,
	["getproto"]=true, ["getconstant2"]=true, ["setupvalue"]=true,
	["setconstant"]=true, ["setreadonly"]=true, ["isreadonly"]=true,
	["queue_on_teleport"]=true, ["queueonteleport"]=true,
	["writefile"]=true, ["readfile"]=true, ["appendfile"]=true,
	["makefolder"]=true, ["isfolder"]=true, ["listfiles"]=true,
	["delfile"]=true, ["delfolder"]=true, ["isfile"]=true,
	["request"]=true, ["http_request"]=true, ["httpRequest"]=true,
	["syn"]=true, ["shared"]=true, ["identifyexecutor"]=true,
	["getexecutorname"]=true, ["getexecutor"]=true, ["isexecutor"]=true,
	["gethud"]=true, ["gethui"]=true, ["getregistry"]=true, ["getgc"]=true,
	["collectgarbage0"]=true, ["signal"]=true, ["Synapse"]=true, ["Fluxus"]=true,
	["Krnl"]=true, ["Solara"]=true, ["Delta"]=true, ["Luraph"]=true,
	["ScriptDumper"]=true, ["Executor"]=true, ["COMMAND_ID"]=true,
	["getcustomattribute"]=true, ["setcustomattribute"]=true,
	["setscriptable"]=true, ["getscriptable"]=true, ["clone"]=true,
}

local SCAN_LIMIT = 700000

local function scanNames(src)
	local seen, order = {}, {}
	local n = #src
	if n > SCAN_LIMIT then n = SCAN_LIMIT end
	local i = 1
	while i <= n do
		local c = src:sub(i, i)
		if c == "-" and src:sub(i, i + 1) == "-" then
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
			i = (e and e + #close) or (n + 1)
		elseif c == '"' or c == "'" then
			local quote = c
			local j = i + 1
			while j <= n do
				local ch = src:sub(j, j)
				if ch == "\\" then j = j + 2
				elseif ch == quote then j = j + 1 break
				elseif ch == "\n" then break
				else j = j + 1 end
			end
			i = j
		elseif c:match("[%a_]") then
			local j = i
			while j <= n and src:sub(j, j):match("[%w_]") do j = j + 1 end
			local name = src:sub(i, j - 1)
			-- member-access (table.concat, obj:Method) — это НЕ глобал
			local p = i - 1
			while p >= 1 and src:sub(p, p):match("%s") do p = p - 1 end
			local isMember = p >= 1 and (src:sub(p, p) == "." or src:sub(p, p) == ":")
			if not isMember and not LUA_KEYWORDS[name] and not KNOWN_GLOBALS[name]
				and not seen[name] then
				seen[name] = true
				order[#order + 1] = name
			end
			i = j
		else
			i = i + 1
		end
	end
	return order
end

-- имена, объявленные самим исходником (local/function/параметры) — отбрасываем
local function declaredNames(src)
	local out = {}
	local n = #src
	if n > SCAN_LIMIT then n = SCAN_LIMIT end
	local head = src:sub(1, n)
	for m in head:gmatch("local%s+([%a_][%w_]*)") do out[m] = true end
	for m in head:gmatch("local%s+[%a_][%w_]*%s*,%s*([%a_][%w_]*)") do out[m] = true end
	for m in head:gmatch("local%s+[%a_][%w_]*%s*,%s*[%a_][%w_]*%s*,%s*([%a_][%w_]*)") do out[m] = true end
	for m in head:gmatch("function%s+([%a_][%w_]*)") do out[m] = true end
	-- параметры: function name(a, b) и function(a, b)
	for m in head:gmatch("function%s+[%a_][%w_]*%s*%(([^%)]*)%)") do
		for p in m:gmatch("[%a_][%w_]*") do out[p] = true end
	end
	for m in head:gmatch("function%s*%(([^%)]*)%)") do
		for p in m:gmatch("[%a_][%w_]*") do out[p] = true end
	end
	-- for k, v in ... (gmatch отдаёт только ПЕРВЫЙ захват в переменную цикла,
	-- поэтому второе имя обязано идти в отдельную переменную)
	for k, v in head:gmatch("for%s+([%a_][%w_]*)%s*,%s*([%a_][%w_]*)%s+in") do
		if k then out[k] = true end
		if v then out[v] = true end
	end
	return out
end

function S.reportGlobals(src, id)
	local used = scanNames(src)
	local declared = declaredNames(src)
	local missing = {}
	for _, name in ipairs(used) do
		if not declared[name] then
			local v = rawget(genv, name)
			if v == nil then v = rawget(_G, name) end
			if v == nil then missing[#missing + 1] = name end
		end
	end
	if #missing > 0 then
		S.missingBuf = S.missingBuf or {}
		table.insert(S.missingBuf, string.format(
			"=== chunk #%d (%d символов): глобалы, которых НЕТ в окружении (%d) ===\n  %s",
			id, #src, #missing, table.concat(missing, ", ")))
		S.save("MISSING_GLOBALS.txt", table.concat(S.missingBuf, "\n\n") .. "\n")
		S.log("MISSING globals chunk #" .. id .. " (" .. #missing .. "): " .. table.concat(missing, ", "))
	end
	return missing
end

-- персистентный proxy: любое обращение к полю даёт вызываемую заглушку
local function makeProxy(name)
	local proxy
	proxy = setmetatable({}, {
		__index = function(_, k)
			local fn = function() return proxy end
			rawset(proxy, k, fn)
			return fn
		end,
		__call = function() return proxy end,
		__tostring = function() return "[proxy " .. tostring(name) .. "]" end,
	})
	return proxy
end

local function installExtraShims()
	if type(rawget(_G, "newproxy")) ~= "function" and type(rawget(genv, "newproxy")) ~= "function" then
		applyShim("newproxy", function(addMt)
			local t = {}
			if addMt then setmetatable(t, {}) end
			return t
		end)
		S.shims.newproxy = "создан (таблица вместо proxy userdata)"
	end

	-- require: чтобы не было "attempt to call a nil value"
	if type(rawget(_G, "require")) ~= "function" and type(rawget(genv, "require")) ~= "function" then
		local reqShim = function(mod)
			if type(mod) == "number" then return nil, "require(" .. tostring(mod) .. ") недоступен" end
			return makeProxy("require:" .. tostring(mod))
		end
		applyShim("require", reqShim)
		S.shims.require = "создан (персистентный proxy)"
	end

	-- определение эксплоита — многие payload'ы зовут это первым делом
	if type(rawget(_G, "identifyexecutor")) ~= "function" then
		applyShim("identifyexecutor", function() return "Dumper" end)
		S.shims.identifyexecutor = "создан (возвращает Dumper)"
	end
	if type(rawget(_G, "getexecutorname")) ~= "function" then
		applyShim("getexecutorname", function() return "Dumper" end)
		S.shims.getexecutorname = "создан (возвращает Dumper)"
	end

	if type(rawget(_G, "hookfunction")) ~= "function" then
		applyShim("hookfunction", function(target, repl)
			-- target может быть чем угодно; rawset требует таблицу
			if type(target) == "table" and type(repl) == "function" then
				pcall(rawset, target, "__dumperHook", true)
			end
			return function(...) end
		end)
		S.shims.hookfunction = "создан (no-op)"
	end
	if type(rawget(_G, "getgc")) ~= "function" then
		applyShim("getgc", function() return {} end)
		S.shims.getgc = "создан (пустой)"
	end
end

local function installAll()
	hookCount = 0
	install("loadstring", "loadstring")
	install("load", "load")
	patchHttpService()
	patchGame()
	installRequest("request", genv)
	installRequest("http_request", genv)
	local synTbl = rawget(genv, "syn")
	if type(synTbl) == "table" then
		installRequest("request", synTbl)
		installRequest("http_request", synTbl)
	end
	installEnvHooks()
	S.scanRemotes()
	installShims()
	installExtraShims()
	S.log("hooks total: " .. tostring(hookCount))
	return hookCount
end

installAll()

---------------------------------------------------------------------------
-- 12. СТАТУС / САМОТЕСТ / ИНСТРУКЦИЯ
---------------------------------------------------------------------------
local function capReport()
	local names = {
		"writefile", "readfile", "makefolder", "isfolder", "appendfile",
		"loadstring", "load", "request", "http_request", "syn", "shared",
		"getconstants", "getprotos", "getupvalues", "getconstant", "getupvalue",
		"getnamecallmethod", "hookmetamethod", "newcclosure", "newproxy",
		"checkcaller", "checknamecall", "getcallingscript", "getgenv", "getrenv",
		"setfenv", "getfenv", "debug", "bit32", "bit", "buffer",
		"coroutine", "unpack", "select", "os", "io", "buffer",
		"require", "hookfunction", "getgc", "identifyexecutor", "getexecutorname",
	}
	local out = { "=== CAPABILITIES ===" }
	for _, n in ipairs(names) do
		local v = rawget(genv, n)
		if v == nil then v = rawget(_G, n) end
		out[#out + 1] = string.format("%-22s %s", n, type(v))
	end
	table.insert(out, "")
	table.insert(out, "=== HOOKS INSTALLED: " .. tostring(hookCount) .. " ===")
	table.insert(out, "game namecall hooked : " .. tostring(S.prev.gameNC ~= nil))
	table.insert(out, "http namecall hooked : " .. tostring(S.prev.httpNC ~= nil))
	table.insert(out, "native closure      : " .. tostring(S.cfg.native)
		.. " (" .. tostring(S.cap.nativeProbe) .. ")")
	local classes = 0
	for _ in pairs(S.remHooked) do classes = classes + 1 end
	table.insert(out, "remote classes      : " .. tostring(classes))
	table.insert(out, "remote fire calls   : " .. tostring(S.remoteTotal))
	table.insert(out, "")
	table.insert(out, "=== SHIMS (не хватало API для payload) ===")
	if type(S.shims) == "table" then
		local names = {}
		for k in pairs(S.shims) do names[#names + 1] = k end
		table.sort(names)
		for _, k in ipairs(names) do
			table.insert(out, string.format("%-10s %s", k, tostring(S.shims[k])))
		end
	end
	table.insert(out, "session dir         : " .. tostring(S.dir))
	return table.concat(out, "\n")
end

local function selfTest()
	local out = { "=== SELF TEST ===" }
	local ok, res = pcall(loadstring, "return __DUMPER_PROBE__")
	if ok and type(res) == "function" then
		local rok, val = pcall(res)
		if rok and val == "__DUMPER_PROBE__" then
			table.insert(out, "loadstring: OK (компилируется и выполняется)")
		else
			table.insert(out, "loadstring: компилируется, запуск вернул " .. tostring(val))
		end
	else
		table.insert(out, "loadstring: FAIL -> " .. tostring(res))
	end
	if type(load) == "function" then
		local ok2, r2 = pcall(load, "return 1+1", "=probe")
		table.insert(out, "load: " .. ((ok2 and type(r2) == "function") and "OK"
			or ("FAIL -> " .. tostring(r2))))
	end
	table.insert(out, "перехват исходника : " .. (S.probeCaptured and "ДА (хук живой)" or "НЕТ — хук не сработал"))
	table.insert(out, "chunks перехвачено : " .. tostring(S.counter))
	table.insert(out, "http перехвачено   : " .. tostring(S.httpCount))
	table.insert(out, "функций разобрано  : " .. tostring(S.walkCount))
	table.insert(out, "строк собрано      : " .. tostring(S.stringCount))
	table.insert(out, "дублей отброшено   : " .. tostring(S.dupes))
	table.insert(out, "lastECR            : " .. tostring(S.lastEcr))
	return table.concat(out, "\n")
end

local HINT = [==[
=== КАК ЧИТАТЬ РЕЗУЛЬТАТ ===
scripts/NNN_*.lua          — обычный текстовый исходник (то, что ушло в loadstring/load)
scripts/NNN_*.chunk.bin    — байты, которые скрипт ПЕРЕДАЛ в load() (у Luraph это байткод)
scripts/NNN_*.dump.bin     — string.dump() скомпилированной функции (чистый байткод Luau)
scripts/NNN_*.ecr.lua      — авто-расшифрованный ECR-контейнер ("\27LUA")
*_bc_strings.txt           — строковые константы, вытащенные из байткода
*_head.txt                 — hex-заголовок + printable-прогоны (диагностика формата)
*_closure_tree.txt         — дерево замыканий, константы и upvalues
luraph_strings.txt         — все строки из getconstants/getupvalues
luraph_urls.txt            — найденные URL / webhook / pastebin
remotes_log.txt            — все FireServer/InvokeServer с аргументами
MISSING_GLOBALS.txt        — глобалы из исходников, которых НЕТ в окружении
http/                      — всё, что скачали по сети
_ALL_SOURCE.lua            — все текстовые исходники склеены

=== КАК ДЕКОМПИЛИРОВАТЬ БАЙТКОД (.dump.bin / .chunk.bin) ===
1) .dump.bin грузится напрямую:  load(readfile(".../001_dump.dump.bin"))()
2) Для ЧИСТОГО Lua-исходника нужен внешний декомпилятор Luau:
     unluau (https://github.com/lunavale/unluau) -> unluau file.dump.bin > out.lua
   Для серии 0.7xx может понадобиться сборка unluau под твою версию Luau.
3) Если файл начинается с "\27LUA" — это ECR-контейнер; ключ подбирается
   автоматически (см. 00_STATUS.txt -> lastECR).

=== ЕСЛИ ПАПКА ПУСТАЯ ===
- Сначала посмотри 00_STATUS.txt: там видно, какие хуки встали, какие API были
  nil и какие шимы поставились (секция SHIMS).
- Если loadstring не перехвачен — запускай ДАМПЕР ПЕРВЫМ, до обфусцированного
  скрипта: Luraph кэширует load() в upvalue на этапе загрузки.
- Если скрипт грузился до дампера — вызси DUMPER_RETRY(), потом DUMPER_DUMP_FN().

=== ЧАСТАЯ ПРИЧИНА ПУСТОЙ ПАПКИ У LURAPH v15 ===
Payload вызывает bit32.band/bxor/countrz/... , setfenv, unpack, load.
Если в эксплоите их нет — VM падает на первой строке (Oq=bit32.band) и
payload не выполняется вообще. Дампер ставит шимы автоматически (секция SHIMS
в 00_STATUS.txt). Если там "НЕ УСТАНОВЛЕН" — env read-only, нужен другой
эксплоит, либо правь окружение руками до запуска payload.

Если появилась ошибка "attempt to call a nil value" — открой
MISSING_GLOBALS.txt: там список имён, которые payload использует как
глобалы, а в окружении их нет. Добавь нужные шимы в секцию 11.7/11.8
или проверь эксплоит.
]==]

S.save("00_STATUS.txt", capReport() .. "\n\n" .. selfTest() .. "\n\n" .. HINT)
S.save("README.txt", HINT)

---------------------------------------------------------------------------
-- 13. РУЧНЫЕ КОМАНДЫ
---------------------------------------------------------------------------
genv.DUMPER_STATUS = function()
	return string.format("dir=%s chunks=%d http=%d fns=%d strings=%d dupes=%d hooks=%d",
		tostring(S.dir), S.counter, S.httpCount, S.walkCount, S.stringCount, S.dupes, hookCount)
end

genv.DUMPER_FLUSH = function()
	S.flushRecon(true)
	S.save("00_STATUS.txt", capReport() .. "\n\n" .. selfTest() .. "\n")
	print("[Dumper] " .. genv.DUMPER_STATUS())
	return S.dir
end

genv.DUMPER_DUMP_FN = function(fn, label)
	S.walkVisited = nil
	pcall(S.walkFn, fn, "manual_" .. tostring(label or "fn"), 0)
	S.flushRecon(true)
	return "dumped " .. tostring(label or "fn")
end

genv.DUMPER_RETRY = function()
	S.walkVisited = nil
	installAll()
	S.save("00_STATUS.txt", capReport() .. "\n\n" .. selfTest() .. "\n")
	print("[Dumper] Re-hook done: " .. genv.DUMPER_STATUS())
	return hookCount
end

S.flushRecon(true)

print("======================================================")
print("  LURAPH v15 DUMPER v2 - RUNNING")
print("  folder: workspace/" .. tostring(S.dir))
print("  hooks: " .. tostring(hookCount) .. "   writefile: " .. tostring(S.hasWrite))
print("  newcclosure: " .. tostring(S.cfg.native) .. " (" .. tostring(S.cap.nativeProbe) .. ")")
print("  now run your obfuscated script")
print("======================================================")
notify("Luraph Dumper v2", "Готов! Папка: " .. tostring(S.dir))
