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
	print("[Dumper] Уже запущен. Для переустановки хуков: DUMPER_RETRY()")
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
S.log("Сессия: workspace/" .. S.dir)

if not S.hasWrite then
	print("[Dumper] ВНИМАНИЕ: в этом эксплоите нет writefile — сохранять НЕКУДА.")
	S.log("writefile отсутствует -> дампы не пишутся на диск")
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
S.cap.nativeProbe = nativeInfo
if userCfg.native == true and not nativeOk then
	S.cfg.native = false
	S.cap.nativeForced = "cfg.native=true, но " .. tostring(nativeInfo)
end

-- Обёртка нативной делается ТОЛЬКО если это безопасно; маркеры нужны, чтобы
-- повторная установка (DUMPER_RETRY) не оборачивала нашу же обёртку.
local function tagHook(fn, base)
	pcall(function() rawset(fn, "__dumperHook", true) end)
	pcall(function() rawset(fn, "__dumperBase", base or fn) end)
	return fn
end

local function baseOf(prev)
	if type(prev) == "function" and rawget(prev, "__dumperHook") then
		local b = rawget(prev, "__dumperBase")
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
		S.log(string.format("дубль #%d (%s) пропущен, len=%d", n, tag, #src))
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
		S.log(string.format("#%d %s БИНАРНЫЙ chunk (%d байт) -> .chunk.bin", n, tag, #src))
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
			S.log("#" .. n .. " ECR расшифрован: " .. tostring(info))
		end
		S.inspectBytecode(base, src, n, tag .. "_chunk")
	else
		S.save(base .. ".lua", hdr .. src)
		table.insert(S.allText, string.format("\n\n-- ==== #%d tag=%s chunk=%s len=%d ====\n%s",
			n, tag, tostring(chunkname), #src, src))
		S.log(string.format("#%d %s ТЕКСТ (%d символов) -> %s.lua", n, tag, #src, base))
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
		S.log("closure tree обрезан на " .. #lines .. " строк")
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
	if rawget(orig, "__dumperHook") then return true, "уже наш хук" end
	local wrapped = buildChunkHook(orig, tag)
	local ok1 = pcall(function() rawset(genv, name, wrapped) end)
	local ok2 = pcall(function() rawset(_G, name, wrapped) end)
	local sharedTbl = rawget(genv, "shared")
	if type(sharedTbl) == "table" and type(rawget(sharedTbl, name)) == "function" then
		pcall(function() rawset(sharedTbl, name, wrapped) end)
	end
	if ok1 or ok2 then
		hookCount = hookCount + 1
		S.log(string.format("хук %s установлен (native=%s)", name, tostring(S.cfg.native)))
		return true, "ok"
	end
	S.log("хук " .. name .. " НЕ установлен (read-only)")
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
	S.log(string.format("HTTP #%d %s %s (%d байт)", n, tostring(method), tostring(url), #body))
	notify("Dumper", "HTTP #" .. n .. " " .. tostring(method) .. " " .. tostring(url):sub(1, 34))
end

local function patchHttpService()
	if type(hookmetamethod) ~= "function" then
		S.log("hookmetamethod нет -> HTTP не перехватывается")
		return false
	end
	local okSvc, svc = pcall(function() return game:GetService("HttpService") end)
	if not okSvc or type(svc) ~= "instance" then
		S.log("HttpService не получен")
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
		S.log("хук HttpService:RequestAsync/GetAsync установлен")
		hookCount = hookCount + 1
		return true
	end
	S.log("хук HttpService НЕ установлен: " .. tostring(prev))
	return false
end

local function patchGame()
	if type(hookmetamethod) ~= "function" then
		S.log("hookmetamethod нет -> game:* не перехватывается")
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
		S.log("хук game:HttpGet*/HttpPost* установлен")
		hookCount = hookCount + 1
		return true
	end
	S.log("хук game НЕ установлен: " .. tostring(prev))
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
	if rawget(orig, "__dumperHook") then return true end
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
		S.log("хук " .. name .. " установлен")
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
		if type(cur) == "function" and not rawget(cur, "__dumperHook") then
			local wrapped = buildChunkHook(cur, name .. "_env")
			if pcall(rawset, env, name, wrapped) then
				S.log("env-таблица пропатчена: " .. name)
			end
		end
	end
end

local function installEnvHooks()
	local origSet = rawget(genv, "setfenv")
	if type(origSet) == "function" and not rawget(origSet, "__dumperHook") then
		local wrapper = function(f, env)
			if type(env) == "table" then pcall(S.patchEnv, env) end
			return origSet(f, env)
		end
		tagHook(wrapper, origSet)
		if pcall(function() rawset(genv, "setfenv", makeNative(wrapper)) end) then
			S.log("хук setfenv установлен")
			hookCount = hookCount + 1
		end
	end

	local origGet = rawget(genv, "getfenv")
	if type(origGet) == "function" and not rawget(origGet, "__dumperHook") then
		local wrapper = function(f)
			local env = origGet(f)
			if type(env) == "table" then pcall(S.patchEnv, env) end
			return env
		end
		tagHook(wrapper, origGet)
		if pcall(function() rawset(genv, "getfenv", makeNative(wrapper)) end) then
			S.log("хук getfenv установлен")
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
	S.log("remote-классов с хуком: " .. tostring(n))

	if not S.descConn then
		pcall(function()
			S.descConn = game.DescendantAdded:Connect(function(inst)
				if REMOTE_CLASSES[inst.ClassName] then pcall(S.hookRemote, inst) end
			end)
		end)
	end
end

---------------------------------------------------------------------------
-- 11. УСТАНОВКА ВСЕГО
---------------------------------------------------------------------------
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
	S.log("всего хуков: " .. tostring(hookCount))
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
		"setfenv", "getfenv", "debug", "bit32", "bit",
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
- Сначала посмотри 00_STATUS.txt: там видно, какие хуки встали.
- Если loadstring не перехвачен — запускай ДАМПЕР ПЕРВЫМ, до обфусцированного
  скрипта: Luraph кэширует load() в upvalue на этапе загрузки.
- Если скрипт грузился до дампера — вызси DUMPER_RETRY(), потом DUMPER_DUMP_FN().
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
	print("[Dumper] Повторная установка хуков: " .. genv.DUMPER_STATUS())
	return hookCount
end

S.flushRecon(true)

print("======================================================")
print("  LURAPH v15 DUMPER v2 — ЗАПУЩЕН")
print("  папка: workspace/" .. tostring(S.dir))
print("  хуков: " .. tostring(hookCount) .. "   writefile: " .. tostring(S.hasWrite))
print("  newcclosure: " .. tostring(S.cfg.native) .. " (" .. tostring(S.cap.nativeProbe) .. ")")
print("  теперь запускай свой обфусцированный скрипт")
print("======================================================")
notify("Luraph Dumper v2", "Готов! Папка: " .. tostring(S.dir))
