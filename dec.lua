--!strict
--[[═══════════════════════════════════════════════════════════════════════════
    SCRIPT GRABBER v2 — ПОЛНЫЙ ПЕРЕХВАТ & ДЕОБФУСКАЦИЯ
    ═══════════════════════════════════════════════════════════════════════════
    Перехватывает ВСЕ основные векторы загрузки скриптов:
      1. loadstring(src)           — основной источник
      2. game:HttpGet(url)         — загрузка исходников по URL
      3. game:HttpGetAsync(url)    — асинхронная загрузка
      4. request / http_request    — полноценные HTTP запросы
      5. require(assetId)          — загрузка ModuleScript из MarketPlace
      6. game:GetObjects(url)      — вставка моделей с вложенными скриптами

    Стелс-режим:
      MAX_CAPTURES: сколько перехватов сделать перед снятием хука (-1 = бесконечно).
      Хуки снимаются ПОСЛЕ N перехватов, а не после первого.

    Декомпиляция:
      Если decompile() есть — используется напрямую.
      Если нет — дампится raw bytecode в hex для офлайн-анализа (unluau, Luau decompiler).

    Запуск: выполни этот скрипт ПЕРВЫМ, потом выполняй целевой.
    Всё сохраняется в workspace/ScriptGrabber/<сессия>/
═══════════════════════════════════════════════════════════════════════════]]

local genv = (typeof(getgenv) == "function") and getgenv() or _G

if genv.__SCRIPT_GRABBER_V2 then
	warn("[Grabber] Уже активен.")
	return
end
genv.__SCRIPT_GRABBER_V2 = true

-- ═══════════════════════════════════════════════════════════════════════════
-- НАСТРОЙКИ
-- ═══════════════════════════════════════════════════════════════════════════
local MAX_CAPTURES      = -1           -- -1 = бесконечно; N = снять хуки после N перехватов
local HOOK_LOADSTRING   = true
local HOOK_HTTPGET      = true
local HOOK_REQUEST      = true
local HOOK_REQUIRE      = true
local HOOK_GETOBJECTS   = true

local MAX_CLEAN_SIZE    = 1024 * 1024  -- раскрытие escape-строк до 1 МБ
local MAX_DECOMP_SIZE   = 1024 * 1024  -- decompile() до 1 МБ
local MAX_FUNCDUMP_SRC  = 2 * 1024 * 1024
local MAX_PROTOS        = 500
local MAX_FUNC_LINES    = 20000
local YIELD_INTERVAL    = 256 * 1024   -- yield каждые N символов чтобы не вешать Roblox
local MAX_BYTECODE_HEX  = 512 * 1024   -- hex-дамп байткода до 512 КБ

-- ═══════════════════════════════════════════════════════════════════════════
-- ОБНАРУЖЕНИЕ ВОЗМОЖНОСТЕЙ ЭКСПЛОЙТА
-- ═══════════════════════════════════════════════════════════════════════════
local HAS_FS = (typeof(writefile) == "function")
	and (typeof(isfolder) == "function")
	and (typeof(makefolder) == "function")

local dbg_getinfo: ((any) -> {[string]: any})? =
	(typeof(debug) == "table" and typeof(debug.getinfo) == "function") and debug.getinfo or nil

local getconstants_fn: ((any) -> {any})? =
	(typeof(getconstants) == "function") and getconstants or nil

local getupvalues_fn: ((any) -> {any})? =
	(typeof(getupvalues) == "function") and getupvalues or nil

local getprotos_fn: ((any) -> {any})? =
	(typeof(getprotos) == "function") and getprotos or nil

local decompile_fn: ((any) -> string)? =
	(typeof(decompile) == "function") and decompile or nil

local getscriptbytecode_fn: ((any) -> string)? =
	(typeof(getscriptbytecode) == "function") and getscriptbytecode or nil

local hookfunction_fn: ((any, any) -> any)? =
	(typeof(hookfunction) == "function") and hookfunction or nil

local hookmetamethod_fn: ((any, string, any) -> any)? =
	(typeof(hookmetamethod) == "function") and hookmetamethod or nil

local getnamecallmethod_fn: (() -> string)? =
	(typeof(getnamecallmethod) == "function") and getnamecallmethod or nil

-- ═══════════════════════════════════════════════════════════════════════════
-- СЕССИЯ И СЧЁТЧИКИ
-- ═══════════════════════════════════════════════════════════════════════════
local ROOT = "ScriptGrabber"
local sessionName: string
do
	local ok, stamp = pcall(os.date, "%Y-%m-%d_%H-%M-%S")
	sessionName = (ok and type(stamp) == "string") and stamp or tostring(math.floor(tick()))
end
local SESSION = ROOT .. "/" .. sessionName

local dumpCount  = 0
local httpCount  = 0
local totalCaptures = 0

-- Таблица для снятия хуков (оригинальные функции)
local originals: {[string]: any} = {}
local hookActive: {[string]: boolean} = {
	loadstring = false,
	httpget = false,
	request = false,
	require_hook = false,
	getobjects = false,
}

-- ═══════════════════════════════════════════════════════════════════════════
-- УТИЛИТЫ
-- ═══════════════════════════════════════════════════════════════════════════
local function notify(title: string, text: string, dur: number?)
	pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification", {
			Title = title,
			Text = text,
			Duration = dur or 4,
		})
	end)
end

local function ensureDir(path: string)
	if not HAS_FS then return end
	if not isfolder(path) then pcall(makefolder, path) end
end

local function saveFile(path: string, content: string)
	if not HAS_FS then
		warn("[Grabber] FS недоступна, вывод в консоль: " .. path)
		print(tostring(content))
		return
	end
	local ok, err = pcall(writefile, path, tostring(content))
	if not ok then
		warn("[Grabber] Ошибка записи '" .. path .. "': " .. tostring(err))
	end
end

local function sanitizeFilename(s: string): string
	return tostring(s):gsub("[^%w%.%-_]", "_"):sub(1, 60)
end

local function checkCaptureLimit(): boolean
	if MAX_CAPTURES < 0 then return false end
	totalCaptures += 1
	return totalCaptures >= MAX_CAPTURES
end

local function unhookAll()
	-- loadstring
	if hookActive.loadstring and originals.loadstring then
		pcall(function() genv.loadstring = originals.loadstring end)
		hookActive.loadstring = false
		print("[Grabber] Хук loadstring снят")
	end
	-- request / http_request
	if hookActive.request then
		for _, name in ipairs({"request", "http_request"}) do
			if originals[name] then
				pcall(function() genv[name] = originals[name] end)
			end
		end
		hookActive.request = false
		print("[Grabber] Хуки request сняты")
	end
	-- require
	if hookActive.require_hook and originals.require_hook then
		pcall(function() genv.require = originals.require_hook end)
		hookActive.require_hook = false
		print("[Grabber] Хук require снят")
	end
	-- httpget и getobjects через __namecall не снимаем — повторный hookmetamethod крашит
	-- Вместо этого ставим флаг и хук сам переходит в прозрачный режим
	hookActive.httpget = false
	hookActive.getobjects = false
	print("[Grabber] Все хуки деактивированы (стелс)")
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ПАРСЕР ESCAPE-ПОСЛЕДОВАТЕЛЬНОСТЕЙ В СТРОКОВЫХ ЛИТЕРАЛАХ
-- ═══════════════════════════════════════════════════════════════════════════
-- Обфускаторы прячут строки в \xNN, \ddd, \u{HHHH}, \z — раскрываем их
-- внутри строковых литералов, не трогая код вне строк.

local function decodeEscapedBody(body: string): string?
	if not body:find("\\", 1, true) then return nil end

	local s = body:gsub("\\z%s+", "")
	s = s:gsub("\\u%{(%x+)%}", function(hex: string): string
		local cp = tonumber(hex, 16) or 0xFFFD
		local ok, ch = pcall(utf8.char, cp)
		return (ok and ch) or "?"
	end)
	s = s:gsub("\\x(%x%x)", function(h: string): string
		return string.char(tonumber(h, 16) or 63)
	end)
	s = s:gsub("\\(%d%d?%d?)", function(d: string): string
		local num = tonumber(d)
		if num and num < 256 then return string.char(num) end
		return "\\" .. d
	end)
	s = s:gsub("\\a", "\a")
	s = s:gsub("\\b", "\b")
	s = s:gsub("\\f", "\f")
	s = s:gsub("\\n", "\n")
	s = s:gsub("\\r", "\r")
	s = s:gsub("\\t", "\t")
	s = s:gsub("\\v", "\v")
	s = s:gsub("\\\\", "\\")
	s = s:gsub("\\'", "'")
	s = s:gsub('\\"', '"')

	if s == body then return nil end
	return s
end

-- Полный лексер строковых литералов:
-- Корректно обрабатывает:
--   "...", '...', [[...]], [=[...]=], [==[...]==] и т.д.
--   -- однострочные комментарии
--   --[[ многострочные комментарии ]]
local function unescapeSource(src: string): string
	if type(src) ~= "string" or #src == 0 then return src end
	if #src > MAX_CLEAN_SIZE then
		return "-- (исходник " .. #src .. " символов — слишком большой для раскрытия, смотри script.txt)"
	end

	local out: {string} = {}
	local i = 1
	local n = #src

	while i <= n do
		local b = src:byte(i)

		-- ─── Комментарии ───
		if b == 45 and i < n and src:byte(i + 1) == 45 then -- "--"
			-- Проверяем многострочный комментарий --[[ или --[==[
			local eqStart = i + 2
			if eqStart <= n and src:byte(eqStart) == 91 then -- "["
				local eqCount = 0
				local j = eqStart + 1
				while j <= n and src:byte(j) == 61 do -- "="
					eqCount += 1
					j += 1
				end
				if j <= n and src:byte(j) == 91 then -- второй "["
					-- Многострочный комментарий: ищем закрывающий ]===]
					local closePattern = "]" .. string.rep("=", eqCount) .. "]"
					local closePos = src:find(closePattern, j + 1, true)
					if closePos then
						out[#out + 1] = src:sub(i, closePos + #closePattern - 1)
						i = closePos + #closePattern
					else
						-- Незакрытый — до конца файла
						out[#out + 1] = src:sub(i)
						i = n + 1
					end
					continue
				end
			end
			-- Однострочный комментарий
			local nl = src:find("\n", i, true)
			if nl then
				out[#out + 1] = src:sub(i, nl)
				i = nl + 1
			else
				out[#out + 1] = src:sub(i)
				i = n + 1
			end
			continue
		end

		-- ─── Long strings [[...]] / [=[...]=] ───
		if b == 91 then -- "["
			local eqCount = 0
			local j = i + 1
			while j <= n and src:byte(j) == 61 do
				eqCount += 1
				j += 1
			end
			if j <= n and src:byte(j) == 91 then
				-- Это long string — копируем как есть (escape-ов в них нет по спецификации Lua)
				local closePattern = "]" .. string.rep("=", eqCount) .. "]"
				local closePos = src:find(closePattern, j + 1, true)
				if closePos then
					out[#out + 1] = src:sub(i, closePos + #closePattern - 1)
					i = closePos + #closePattern
				else
					out[#out + 1] = src:sub(i)
					i = n + 1
				end
				continue
			end
		end

		-- ─── Строковые литералы "..." и '...' ───
		if b == 34 or b == 39 then -- двойная или одинарная кавычка
			local quote = b
			local j = i + 1
			local bodyParts: {string} = {}
			local closed = false

			while j <= n do
				local cb = src:byte(j)
				if cb == 92 then -- backslash
					-- Берём экранированный символ
					if j + 1 <= n then
						bodyParts[#bodyParts + 1] = src:sub(j, j + 1)
						j += 2
					else
						bodyParts[#bodyParts + 1] = src:sub(j, j)
						j += 1
					end
				elseif cb == quote then
					closed = true
					break
				elseif cb == 10 or cb == 13 then -- незакрытая строка
					break
				else
					bodyParts[#bodyParts + 1] = src:sub(j, j)
					j += 1
				end
			end

			if closed then
				local rawBody = table.concat(bodyParts)
				local decoded = decodeEscapedBody(rawBody)
				if decoded then
					-- Безопасная проверка: если после раскрытия содержит
					-- символ кавычки того же типа без экранирования — оставляем оригинал
					local safeQuote = string.char(quote)
					if decoded:find(safeQuote, 1, true) then
						-- Вместо ломающей подстановки — оборачиваем в long string если возможно
						if not decoded:find("]]", 1, true) then
							out[#out + 1] = "[[" .. decoded .. "]]"
						elseif not decoded:find("]=]", 1, true) then
							out[#out + 1] = "[=[" .. decoded .. "]=]"
						else
							-- Совсем крайний случай — оставляем оригинал
							out[#out + 1] = src:sub(i, j)
						end
					else
						out[#out + 1] = safeQuote .. decoded .. safeQuote
					end
				else
					out[#out + 1] = src:sub(i, j)
				end
				i = j + 1
			else
				-- Незакрытая строка — копируем как есть
				out[#out + 1] = src:sub(i, j)
				i = j + 1
			end

			-- Yield чтобы не вешать Roblox
			if i > 0 and (i % YIELD_INTERVAL) < 128 then pcall(task.wait) end
			continue
		end

		-- ─── Обычный символ ───
		out[#out + 1] = src:sub(i, i)
		i += 1
	end

	return table.concat(out)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- HEX DUMP БАЙТКОДА (фоллбэк когда нет decompile)
-- ═══════════════════════════════════════════════════════════════════════════
local function bytecodeHexDump(bc: string): string
	local lines: {string} = {}
	lines[#lines + 1] = "-- RAW BYTECODE HEX DUMP"
	lines[#lines + 1] = "-- Длина: " .. #bc .. " байт"
	lines[#lines + 1] = "-- Для офлайн-декомпиляции используй unluau / Luau Decompiler"
	lines[#lines + 1] = ""

	local limit = math.min(#bc, MAX_BYTECODE_HEX)
	for offset = 0, limit - 1, 16 do
		local hex: {string} = {}
		local ascii: {string} = {}
		for col = 0, 15 do
			local pos = offset + col + 1
			if pos > limit then
				hex[#hex + 1] = "  "
				ascii[#ascii + 1] = " "
			else
				local byte = bc:byte(pos)
				hex[#hex + 1] = string.format("%02X", byte)
				if byte >= 32 and byte <= 126 then
					ascii[#ascii + 1] = string.char(byte)
				else
					ascii[#ascii + 1] = "."
				end
			end
		end
		lines[#lines + 1] = string.format(
			"%08X  %s %s %s %s  %s %s %s %s  %s %s %s %s  %s %s %s %s  |%s|",
			offset,
			hex[1], hex[2], hex[3], hex[4],
			hex[5], hex[6], hex[7], hex[8],
			hex[9], hex[10], hex[11], hex[12],
			hex[13], hex[14], hex[15], hex[16],
			table.concat(ascii)
		)

		if (offset % (64 * 1024)) == 0 and offset > 0 then
			pcall(task.wait)
		end
	end

	if limit < #bc then
		lines[#lines + 1] = ""
		lines[#lines + 1] = "-- (обрезано: показано " .. limit .. " из " .. #bc .. " байт)"
	end

	return table.concat(lines, "\n")
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ДАМП ФУНКЦИЙ (прото-дерево, константы, upvalue)
-- ═══════════════════════════════════════════════════════════════════════════
local funcDumpLines: {string} = {}
local funcDumpLineCount = 0

local function addFuncLine(s: string)
	if funcDumpLineCount < MAX_FUNC_LINES then
		funcDumpLineCount += 1
		funcDumpLines[funcDumpLineCount] = s
	end
end

local function prettyValue(v: any): string
	local t = typeof(v)
	if t == "string" then
		local s = tostring(v):gsub("%c", " ")
		if #s > 400 then s = s:sub(1, 400) .. "…(+" .. (#s - 400) .. ")" end
		return string.format("%q", s)
	elseif t == "number" then
		return tostring(v)
	elseif t == "boolean" then
		return tostring(v)
	elseif t == "nil" then
		return "nil"
	elseif t == "table" then
		return "<table>"
	elseif t == "function" then
		return "<function>"
	elseif t == "Instance" then
		local ok, cls = pcall(function() return v.ClassName end)
		return "<Instance: " .. (ok and tostring(cls) or "?") .. ">"
	end
	return "<" .. t .. ">"
end

local function dumpClosureRecursive(fn: any, name: string, depth: number, srcLen: number)
	if depth > 30 then return end
	if srcLen > MAX_FUNCDUMP_SRC then return end

	local info: {[string]: any} = {}
	if dbg_getinfo then
		pcall(function()
			info = (dbg_getinfo :: any)(fn) or {}
		end)
	end

	local pad = string.rep("  ", depth)
	addFuncLine(string.format(
		"%s%s = function(...)  -- [%s] L%s..%s what=%s params=%s vararg=%s",
		pad, name,
		tostring(info.short_src or info.source or "?"),
		tostring(info.linedefined or 0),
		tostring(info.lastlinedefined or 0),
		tostring(info.what or "?"),
		tostring(info.nparams or "?"),
		tostring((info.is_vararg == 1 or info.is_vararg == true) and "yes" or "no")
	))

	-- Upvalues
	if getupvalues_fn then
		local ok, uvs = pcall(getupvalues_fn :: any, fn)
		if ok and type(uvs) == "table" then
			local count = 0
			for idx, uv in pairs(uvs) do
				count += 1
				if count > 50 then
					addFuncLine(pad .. "  (ещё upvalue — обрезано)")
					break
				end
				addFuncLine(pad .. "  upvalue[" .. tostring(idx) .. "] = " .. prettyValue(uv))
			end
		end
	end

	-- Constants
	if getconstants_fn then
		local ok, consts = pcall(getconstants_fn :: any, fn)
		if ok and type(consts) == "table" then
			local parts: {string} = {}
			local shown = 0
			for i, c in ipairs(consts) do
				shown += 1
				if shown > 200 then
					parts[#parts + 1] = "… (ещё " .. (#consts - 200) .. " констант)"
					break
				end
				parts[#parts + 1] = prettyValue(c)
			end
			if #parts > 0 then
				addFuncLine(pad .. "  constants (" .. #consts .. "): " .. table.concat(parts, ", "))
			end
		end
	end

	-- Proto functions (рекурсивно)
	if getprotos_fn then
		local ok, protos = pcall(getprotos_fn :: any, fn)
		if ok and type(protos) == "table" then
			local dumped = 0
			for i, proto in ipairs(protos) do
				if dumped >= MAX_PROTOS then
					addFuncLine(pad .. "  … (показано " .. dumped .. " из " .. #protos .. " прото)")
					break
				end
				if typeof(proto) == "function" then
					dumped += 1
					local okR, errR = pcall(dumpClosureRecursive, proto, name .. ".proto" .. i, depth + 1, srcLen)
					if not okR then
						addFuncLine(pad .. "  (ошибка дампа proto" .. i .. ": " .. tostring(errR) .. ")")
					end
					if (dumped % 30) == 0 then pcall(task.wait) end
				end
			end
		end
	end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ОСНОВНОЙ ДАМП СКРИПТА
-- ═══════════════════════════════════════════════════════════════════════════
local function saveDump(chunkName: string?, source: string?, fn: any, errText: string?)
	dumpCount += 1
	local folder = SESSION .. "/dump_" .. dumpCount
	ensureDir(folder)

	local srcLen = (type(source) == "string") and #source or 0

	-- ─── 1. Исходник → script.txt ───
	saveFile(folder .. "/script.txt", table.concat({
		"-- ══ ScriptGrabber v2 ══",
		"-- chunk: " .. tostring(chunkName or "loadstring"),
		"-- source length: " .. srcLen .. " chars",
		"-- capture #" .. dumpCount,
		"",
		tostring(source or "(исходник недоступен)"),
	}, "\n"))

	-- ─── 2. Раскрытые строки → script_clean.txt ───
	if type(source) == "string" and srcLen > 0 then
		local okClean, cleanResult = pcall(unescapeSource, source)
		if okClean and type(cleanResult) == "string" then
			saveFile(folder .. "/script_clean.txt", cleanResult)
		else
			saveFile(folder .. "/script_clean.txt",
				"-- Ошибка раскрытия строк: " .. tostring(cleanResult))
		end
	end

	-- ─── 3. Дамп функций → functions.txt ───
	funcDumpLines = {"=== Дамп функций: " .. tostring(chunkName or "loadstring") .. " ==="}
	funcDumpLineCount = 1

	if errText then
		addFuncLine("(!) Ошибка компиляции: " .. errText)
	end

	if fn then
		if srcLen <= MAX_FUNCDUMP_SRC then
			local okDump, errDump = pcall(dumpClosureRecursive, fn, "chunk", 0, srcLen)
			if not okDump then
				addFuncLine("(дамп функций прерван: " .. tostring(errDump) .. ")")
			end
		else
			addFuncLine("(исходник " .. srcLen .. " символов — слишком большой для дампа функций)")
		end
	else
		addFuncLine("(функция не создана — скрипт не скомпилировался)")
	end
	saveFile(folder .. "/functions.txt", table.concat(funcDumpLines, "\n", 1, funcDumpLineCount))

	-- ─── 4. Декомпиляция → decompiled.txt ───
	if fn and decompile_fn and srcLen <= MAX_DECOMP_SIZE then
		local ok, res = pcall(decompile_fn :: any, fn)
		if ok and type(res) == "string" and #res > 0 then
			saveFile(folder .. "/decompiled.txt", res)
		else
			-- Фоллбэк: decompile не сработал — пробуем hex dump
			saveFile(folder .. "/decompiled.txt",
				"-- decompile() вернул ошибку: " .. tostring(res) .. "\n-- Смотри bytecode_hex.txt")
			if getscriptbytecode_fn and fn then
				local okBc, bc = pcall(getscriptbytecode_fn :: any, fn)
				if okBc and type(bc) == "string" then
					saveFile(folder .. "/bytecode_hex.txt", bytecodeHexDump(bc))
				end
			end
		end
	elseif fn and not decompile_fn then
		-- Нет decompile — дампим байткод в hex если можем
		local bcDumped = false
		if getscriptbytecode_fn then
			local okBc, bc = pcall(getscriptbytecode_fn :: any, fn)
			if okBc and type(bc) == "string" and #bc > 0 then
				saveFile(folder .. "/bytecode_hex.txt", bytecodeHexDump(bc))
				saveFile(folder .. "/bytecode_raw.bin", bc)
				bcDumped = true
			end
		end
		saveFile(folder .. "/decompiled.txt", table.concat({
			"-- decompile() отсутствует в этом эксплойте.",
			bcDumped and "-- Байткод сохранён в bytecode_hex.txt и bytecode_raw.bin" or "-- getscriptbytecode тоже недоступен.",
			"-- Для офлайн-декомпиляции используй unluau или Luau Decompiler на ПК.",
			"-- Исходник как есть лежит в script.txt / script_clean.txt",
		}, "\n"))
	elseif fn and decompile_fn and srcLen > MAX_DECOMP_SIZE then
		saveFile(folder .. "/decompiled.txt", table.concat({
			"-- Чанк слишком большой (" .. srcLen .. " символов) — decompile() по таким может крашить.",
			"-- Декомпилируй вручную (unluau / Luau Decompiler).",
		}, "\n"))
		-- Но байткод всё равно пробуем сохранить
		if getscriptbytecode_fn then
			local okBc, bc = pcall(getscriptbytecode_fn :: any, fn)
			if okBc and type(bc) == "string" and #bc > 0 then
				saveFile(folder .. "/bytecode_raw.bin", bc)
			end
		end
	else
		saveFile(folder .. "/decompiled.txt",
			"-- Нет ни функции, ни decompile — скрипт не загрузился.")
	end

	-- ─── 5. Хеш исходника для быстрого поиска дубликатов ───
	if type(source) == "string" and srcLen > 0 then
		-- Простой FNV-1a 32-bit хеш для идентификации дублей
		local hash: number = 2166136261
		local len = math.min(srcLen, 8192) -- хешируем первые 8 КБ
		for ci = 1, len do
			hash = bit32.bxor(hash, source:byte(ci))
			-- hash * 16777619, но Luau числа double — ок для 32 бит
			hash = bit32.band(hash * 16777619, 0xFFFFFFFF)
		end
		saveFile(folder .. "/meta.txt", table.concat({
			"chunk=" .. tostring(chunkName or "loadstring"),
			"source_len=" .. srcLen,
			"source_hash=" .. string.format("%08X", hash),
			"capture_index=" .. dumpCount,
			"has_function=" .. tostring(fn ~= nil),
			"has_decompile=" .. tostring(decompile_fn ~= nil),
		}, "\n"))
	end

	print("[Grabber] Перехват #" .. dumpCount .. " → " .. folder)
	notify("Grabber", "#" .. dumpCount .. " сохранён", 3)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- СОХРАНЕНИЕ HTTP-ОТВЕТА
-- ═══════════════════════════════════════════════════════════════════════════
local function saveHttpResponse(url: string, body: string, method: string)
	httpCount += 1
	local fname = "http_" .. httpCount .. "_" .. sanitizeFilename(url) .. ".lua"
	saveFile(SESSION .. "/" .. fname, table.concat({
		"-- URL: " .. url,
		"-- Method: " .. method,
		"-- Length: " .. #body .. " chars",
		"",
		body,
	}, "\n"))
	print("[Grabber] HTTP сохранён → " .. fname)

	-- Если ответ похож на Lua/Luau код — дополнительно прогоняем через дамп
	if body:find("function", 1, true) or body:find("local ", 1, true) or body:find("return ", 1, true) then
		task.spawn(function()
			local origLs = originals.loadstring or genv.loadstring
			if typeof(origLs) == "function" then
				local okCompile, fn, err = pcall(origLs, body, url)
				if okCompile and typeof(fn) == "function" then
					saveDump("http:" .. url, body, fn, nil)
				elseif okCompile and typeof(err) == "string" then
					saveDump("http:" .. url, body, nil, err)
				end
			end
		end)
	end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ДАМП СКРИПТОВ ИЗ ЭКЗЕМПЛЯРА (LocalScript / ModuleScript)
-- ═══════════════════════════════════════════════════════════════════════════
local function dumpScriptInstance(inst: Instance, label: string)
	dumpCount += 1
	local safeName = sanitizeFilename(inst.Name)
	local folder = SESSION .. "/instance_" .. dumpCount .. "_" .. safeName
	ensureDir(folder)

	-- Source
	local okSrc, src = pcall(function() return (inst :: any).Source end)
	if okSrc and type(src) == "string" and #src > 0 then
		saveFile(folder .. "/script.txt", src)
		local okClean, clean = pcall(unescapeSource, src)
		if okClean and type(clean) == "string" then
			saveFile(folder .. "/script_clean.txt", clean)
		end
	else
		saveFile(folder .. "/script.txt",
			"-- Source недоступен (эксплойт не может читать исходники игры)")
	end

	-- Bytecode
	if getscriptbytecode_fn then
		local okBc, bc = pcall(getscriptbytecode_fn :: any, inst)
		if okBc and type(bc) == "string" and #bc > 0 then
			saveFile(folder .. "/bytecode_raw.bin", bc)
			saveFile(folder .. "/bytecode_hex.txt", bytecodeHexDump(bc))
		end
	end

	-- Decompile
	if decompile_fn then
		local okDec, dec = pcall(decompile_fn :: any, inst)
		if okDec and type(dec) == "string" and #dec > 0 then
			saveFile(folder .. "/decompiled.txt", dec)
		else
			-- Попробуем декомпилировать source если есть
			if okSrc and type(src) == "string" then
				local okDec2, dec2 = pcall(decompile_fn :: any, src)
				if okDec2 and type(dec2) == "string" then
					saveFile(folder .. "/decompiled.txt", dec2)
				else
					saveFile(folder .. "/decompiled.txt",
						"-- decompile() не сработал: " .. tostring(dec))
				end
			else
				saveFile(folder .. "/decompiled.txt",
					"-- decompile() не сработал: " .. tostring(dec))
			end
		end
	end

	saveFile(folder .. "/meta.txt", table.concat({
		"instance_name=" .. inst.Name,
		"class=" .. inst.ClassName,
		"path=" .. label,
		"capture_index=" .. dumpCount,
	}, "\n"))

	print("[Grabber] Instance dump: " .. label .. " → " .. folder)
	notify("Grabber", "Instance #" .. dumpCount .. " saved", 3)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ХУКИ
-- ═══════════════════════════════════════════════════════════════════════════

-- ─── loadstring ───
local function installLoadstringHook()
	if not HOOK_LOADSTRING then return end
	local original = genv.loadstring
	if typeof(original) ~= "function" then
		warn("[Grabber] loadstring не найден")
		return
	end
	originals.loadstring = original

	local wrapped = function(src: any, chunkname: any, ...): any
		local results = table.pack(original(src, chunkname, ...))
		local fn = (typeof(results[1]) == "function") and results[1] or nil
		local err = (fn == nil and results.n >= 2) and tostring(results[2]) or nil

		task.spawn(saveDump, chunkname, src, fn, err)

		if checkCaptureLimit() and hookActive.loadstring then
			unhookAll()
		end
		return table.unpack(results, 1, results.n)
	end

	local okSet = pcall(function() genv.loadstring = wrapped end)
	if okSet then
		hookActive.loadstring = true
	elseif hookfunction_fn then
		pcall(function()
			(hookfunction_fn :: any)(original, wrapped)
			hookActive.loadstring = true
		end)
	else
		warn("[Grabber] Не удалось подменить loadstring")
	end
end

-- ─── __namecall (HttpGet, HttpGetAsync, GetObjects) ───
local function installNamecallHook()
	if not HOOK_HTTPGET and not HOOK_GETOBJECTS then return end
	if not hookmetamethod_fn then
		warn("[Grabber] hookmetamethod недоступен — HttpGet/GetObjects не перехватываются")
		return
	end
	if not getnamecallmethod_fn then
		warn("[Grabber] getnamecallmethod недоступен — __namecall хук бесполезен")
		return
	end

	local ok = pcall(function()
		local old: any
		old = (hookmetamethod_fn :: any)(game, "__namecall", function(self: any, ...: any): any
			local method = (getnamecallmethod_fn :: any)()

			-- HttpGet / HttpGetAsync
			if HOOK_HTTPGET and hookActive.httpget
				and (method == "HttpGet" or method == "HttpGetAsync") then
				local args = table.pack(...)
				local url = tostring(args[1])
				local results = table.pack(old(self, ...))

				if typeof(results[1]) == "string" and #results[1] > 0 then
					task.spawn(saveHttpResponse, url, results[1], method)
					if checkCaptureLimit() then unhookAll() end
				end
				return table.unpack(results, 1, results.n)
			end

			-- GetObjects (InsertService:LoadAsset аналог)
			if HOOK_GETOBJECTS and hookActive.getobjects and method == "GetObjects" then
				local args = table.pack(...)
				local url = tostring(args[1])
				local results = table.pack(old(self, ...))

				if typeof(results[1]) == "table" then
					task.spawn(function()
						for _, obj in ipairs(results[1]) do
							if typeof(obj) == "Instance" then
								if obj:IsA("LocalScript") or obj:IsA("ModuleScript") or obj:IsA("Script") then
									dumpScriptInstance(obj, "GetObjects:" .. url .. "/" .. obj.Name)
								end
								-- Рекурсивно ищем вложенные скрипты
								for _, desc in ipairs(obj:GetDescendants()) do
									if typeof(desc) == "Instance"
										and (desc:IsA("LocalScript") or desc:IsA("ModuleScript") or desc:IsA("Script")) then
										dumpScriptInstance(desc, "GetObjects:" .. url .. "/" .. desc:GetFullName())
									end
								end
							end
						end
					end)
					if checkCaptureLimit() then unhookAll() end
				end
				return table.unpack(results, 1, results.n)
			end

			return old(self, ...)
		end)
	end)

	if ok then
		if HOOK_HTTPGET then hookActive.httpget = true end
		if HOOK_GETOBJECTS then hookActive.getobjects = true end
	else
		warn("[Grabber] __namecall хук не установился")
	end
end

-- ─── request / http_request ───
local function installRequestHook()
	if not HOOK_REQUEST then return end

	for _, name in ipairs({"request", "http_request"}) do
		local original = genv[name]
		if typeof(original) == "function" then
			originals[name] = original
			pcall(function()
				genv[name] = function(opts: any, ...: any): any
					local results = table.pack(original(opts, ...))

					if typeof(opts) == "table" and typeof(opts.Url) == "string"
						and typeof(results[1]) == "table" and typeof(results[1].Body) == "string"
						and #results[1].Body > 0 then
						task.spawn(saveHttpResponse, opts.Url, results[1].Body, name)
						if checkCaptureLimit() then unhookAll() end
					end

					return table.unpack(results, 1, results.n)
				end
				hookActive.request = true
			end)
		end
	end
end

-- ─── require (перехват require(assetId)) ───
local function installRequireHook()
	if not HOOK_REQUIRE then return end
	local original = genv.require
	if typeof(original) ~= "function" then
		warn("[Grabber] require не найден")
		return
	end
	originals.require_hook = original

	local wrapped = function(target: any, ...: any): any
		local results = table.pack(original(target, ...))

		-- Если target — число (assetId), пробуем дампить ModuleScript
		if typeof(target) == "number" then
			task.spawn(function()
				-- Пробуем получить ModuleScript через InsertService
				local okInsert, model = pcall(function()
					return game:GetService("InsertService"):LoadAsset(target)
				end)
				if okInsert and typeof(model) == "Instance" then
					for _, desc in ipairs(model:GetDescendants()) do
						if typeof(desc) == "Instance" and desc:IsA("ModuleScript") then
							dumpScriptInstance(desc, "require(" .. target .. ")/" .. desc:GetFullName())
						end
					end
					pcall(function() model:Destroy() end)
				end
			end)
			if checkCaptureLimit() then unhookAll() end
		elseif typeof(target) == "Instance" and target:IsA("ModuleScript") then
			task.spawn(dumpScriptInstance, target, "require:" .. target:GetFullName())
			if checkCaptureLimit() then unhookAll() end
		end

		return table.unpack(results, 1, results.n)
	end

	local okSet = pcall(function() genv.require = wrapped end)
	if okSet then
		hookActive.require_hook = true
	elseif hookfunction_fn then
		pcall(function()
			(hookfunction_fn :: any)(original, wrapped)
			hookActive.require_hook = true
		end)
	else
		warn("[Grabber] Не удалось подменить require")
	end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- БОНУС: DumpGameScript — ручной дамп любого скрипта из игры
-- ═══════════════════════════════════════════════════════════════════════════
genv.DumpGameScript = function(inst: any)
	if typeof(inst) ~= "Instance" then
		warn("[Grabber] DumpGameScript: передай Instance (LocalScript/ModuleScript/Script)")
		return
	end
	pcall(dumpScriptInstance, inst, "manual:" .. inst:GetFullName())
end

-- ═══════════════════════════════════════════════════════════════════════════
-- БОНУС: DumpAllGameScripts — дамп ВСЕХ скриптов из дерева игры
-- ═══════════════════════════════════════════════════════════════════════════
genv.DumpAllGameScripts = function(root: any?)
	local rootInst: Instance = (typeof(root) == "Instance") and root or game
	local count = 0
	for _, desc in ipairs(rootInst:GetDescendants()) do
		if typeof(desc) == "Instance"
			and (desc:IsA("LocalScript") or desc:IsA("ModuleScript") or desc:IsA("Script")) then
			count += 1
			pcall(dumpScriptInstance, desc, "bulk:" .. desc:GetFullName())
			if (count % 5) == 0 then pcall(task.wait) end
		end
	end
	print("[Grabber] Дампнуто " .. count .. " скриптов из " .. rootInst:GetFullName())
	notify("Grabber", count .. " скриптов дампнуто", 5)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ИНИЦИАЛИЗАЦИЯ
-- ═══════════════════════════════════════════════════════════════════════════
ensureDir(ROOT)
ensureDir(SESSION)

-- Сессионный лог
local capabilitiesReport: {string} = {
	"ScriptGrabber v2 — сессия: " .. sessionName,
	"────────────────────────────────",
	"Эксплойт: " .. tostring((typeof(identifyexecutor) == "function") and identifyexecutor() or "неизвестно"),
	"FS: " .. tostring(HAS_FS),
	"MAX_CAPTURES: " .. (MAX_CAPTURES < 0 and "unlimited" or tostring(MAX_CAPTURES)),
	"",
	"Возможности:",
	"  decompile:           " .. tostring(decompile_fn ~= nil),
	"  getscriptbytecode:   " .. tostring(getscriptbytecode_fn ~= nil),
	"  getconstants:        " .. tostring(getconstants_fn ~= nil),
	"  getupvalues:         " .. tostring(getupvalues_fn ~= nil),
	"  getprotos:           " .. tostring(getprotos_fn ~= nil),
	"  hookfunction:        " .. tostring(hookfunction_fn ~= nil),
	"  hookmetamethod:      " .. tostring(hookmetamethod_fn ~= nil),
	"  getnamecallmethod:   " .. tostring(getnamecallmethod_fn ~= nil),
	"  debug.getinfo:       " .. tostring(dbg_getinfo ~= nil),
	"",
	"Хуки:",
	"  loadstring:          " .. tostring(HOOK_LOADSTRING),
	"  HttpGet/Async:       " .. tostring(HOOK_HTTPGET),
	"  request/http_request:" .. tostring(HOOK_REQUEST),
	"  require(assetId):    " .. tostring(HOOK_REQUIRE),
	"  GetObjects:          " .. tostring(HOOK_GETOBJECTS),
	"",
	"Утилиты:",
	"  DumpGameScript(inst)      — ручной дамп скрипта из игры",
	"  DumpAllGameScripts(root?) — дамп ВСЕХ скриптов (опционально из поддерева)",
	"",
}
saveFile(SESSION .. "/info.txt", table.concat(capabilitiesReport, "\n"))

-- Установка хуков
installLoadstringHook()
installNamecallHook()
installRequestHook()
installRequireHook()

-- Отчёт
local activeHooks: {string} = {}
for name, active in pairs(hookActive) do
	if active then activeHooks[#activeHooks + 1] = name end
end

print("[Grabber] ══ АКТИВЕН ══ Хуки: " .. table.concat(activeHooks, ", "))
print("[Grabber] Всё сохраняется в workspace/" .. SESSION)
notify("Grabber v2", "Активен! " .. #activeHooks .. " хуков", 6)
