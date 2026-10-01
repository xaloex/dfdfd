--!strict
--[[═══════════════════════════════════════════════════════════════════════════
    SCRIPT GRABBER v3 — ПОЛНЫЙ ПЕРЕХВАТ + РАНТАЙМ ДЕОБФУСКАЦИЯ
    ═══════════════════════════════════════════════════════════════════════════
    Три уровня перехвата:

    УРОВЕНЬ 1 — ПЕРЕХВАТ ЗАГРУЗКИ (как раньше):
      loadstring, HttpGet, request, require, GetObjects

    УРОВЕНЬ 2 — РАСКРЫТИЕ СТРОК В ИСХОДНИКЕ:
      \xNN, \ddd, \u{HHHH}, \z → читаемый текст

    УРОВЕНЬ 3 — РАНТАЙМ ШПИОН (НОВОЕ):
      Хукает ВСЕ API которые обфусцированный скрипт вызывает в рантайме:
      • string.char / string.byte / table.concat → ловит строки собираемые в рантайме
      • RemoteEvent:FireServer / RemoteFunction:InvokeServer → ловит сетевые вызовы
      • Instance.new / game:GetService → ловит создание объектов
      • Всё логируется в runtime_spy.txt — ПОЛНАЯ картина что скрипт делает

    Запуск: выполни ПЕРВЫМ, потом целевой скрипт.
    Результат: workspace/ScriptGrabber/<сессия>/
═══════════════════════════════════════════════════════════════════════════]]

local genv = (typeof(getgenv) == "function") and getgenv() or _G

if genv.__SCRIPT_GRABBER_V3 then
	warn("[Grabber] Уже активен.")
	return
end
genv.__SCRIPT_GRABBER_V3 = true

-- ═══════════════════════════════════════════════════════════════════════════
-- НАСТРОЙКИ
-- ═══════════════════════════════════════════════════════════════════════════
local MAX_CAPTURES       = -1          -- -1 = бесконечно
local HOOK_LOADSTRING    = true
local HOOK_HTTPGET       = true
local HOOK_REQUEST       = true
local HOOK_REQUIRE       = true
local HOOK_GETOBJECTS    = true
local HOOK_RUNTIME_SPY   = true        -- рантайм-шпион (ловит всё что скрипт делает)

local MAX_CLEAN_SIZE     = 1024 * 1024
local MAX_DECOMP_SIZE    = 1024 * 1024
local MAX_FUNCDUMP_SRC   = 2 * 1024 * 1024
local MAX_PROTOS         = 500
local MAX_FUNC_LINES     = 20000
local YIELD_INTERVAL     = 256 * 1024
local MAX_BYTECODE_HEX   = 512 * 1024
local MAX_SPY_LINES      = 50000       -- максимум строк в runtime_spy.txt
local SPY_FLUSH_INTERVAL = 200         -- сбрасывать лог каждые N записей
local SPY_STRING_MIN_LEN = 4           -- минимальная длина строки для логирования

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

local checkcaller_fn: (() -> boolean)? =
	(typeof(checkcaller) == "function") and checkcaller or nil

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

local dumpCount     = 0
local httpCount     = 0
local totalCaptures = 0

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

local function appendFile(path: string, content: string)
	if not HAS_FS then return end
	local ok, err = pcall(appendfile, path, content)
	if not ok then
		-- appendfile может не быть — фоллбэк через readfile+writefile
		local existing = ""
		pcall(function() existing = readfile(path) end)
		pcall(writefile, path, existing .. content)
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
	if hookActive.loadstring and originals.loadstring then
		pcall(function() genv.loadstring = originals.loadstring end)
		hookActive.loadstring = false
	end
	if hookActive.request then
		for _, name in ipairs({"request", "http_request"}) do
			if originals[name] then
				pcall(function() genv[name] = originals[name] end)
			end
		end
		hookActive.request = false
	end
	if hookActive.require_hook and originals.require_hook then
		pcall(function() genv.require = originals.require_hook end)
		hookActive.require_hook = false
	end
	hookActive.httpget = false
	hookActive.getobjects = false
	print("[Grabber] Все хуки деактивированы (стелс)")
end

-- ═══════════════════════════════════════════════════════════════════════════
-- РАНТАЙМ ШПИОН — ПЕРЕХВАТ ВСЕХ API ВЫЗОВОВ
-- ═══════════════════════════════════════════════════════════════════════════
-- Обфускаторы (Luraph, IronBrew2, PSU и т.д.) прячут код в кастомную VM.
-- Исходник бесполезен — это интерпретатор. Но в рантайме скрипт ОБЯЗАН
-- вызывать реальные API Roblox. Мы ловим ВСЕ эти вызовы.

local spyLog: {string} = {}
local spyCount = 0
local spyActive = false
local spyStrings: {[string]: boolean} = {}    -- уникальные строки собранные в рантайме
local spyRemotes: {string} = {}               -- все вызовы RemoteEvent/Function
local spyInstances: {string} = {}             -- все Instance.new()
local spyServices: {[string]: boolean} = {}   -- все GetService()

local function spyAdd(category: string, msg: string)
	if spyCount >= MAX_SPY_LINES then return end
	spyCount += 1
	local timestamp = string.format("%.3f", tick() % 10000)
	spyLog[spyCount] = "[" .. timestamp .. "] [" .. category .. "] " .. msg

	-- Периодический сброс на диск
	if (spyCount % SPY_FLUSH_INTERVAL) == 0 then
		task.spawn(function()
			local chunk = table.concat(spyLog, "\n", math.max(1, spyCount - SPY_FLUSH_INTERVAL + 1), spyCount) .. "\n"
			appendFile(SESSION .. "/runtime_spy.txt", chunk)
		end)
	end
end

local function spyAddString(s: string)
	if #s < SPY_STRING_MIN_LEN then return end
	if #s > 2000 then s = s:sub(1, 2000) .. "…(+" .. (#s - 2000) .. ")" end
	-- Фильтруем мусор — только печатные строки
	local printable = 0
	for i = 1, math.min(#s, 200) do
		local b = s:byte(i)
		if (b >= 32 and b <= 126) or b == 10 or b == 13 or b == 9 or b > 127 then
			printable += 1
		end
	end
	if printable < math.min(#s, 200) * 0.6 then return end -- >40% мусора — пропускаем
	if not spyStrings[s] then
		spyStrings[s] = true
		spyAdd("STRING", string.format("%q", s:gsub("%c", " ")))
	end
end

local function installRuntimeSpy()
	if not HOOK_RUNTIME_SPY then return end
	spyActive = true

	-- Сохраняем оригиналы
	local orig_string_char   = string.char
	local orig_string_byte   = string.byte
	local orig_string_sub    = string.sub
	local orig_string_rep    = string.rep
	local orig_string_reverse = string.reverse
	local orig_string_gsub   = string.gsub
	local orig_string_format = string.format
	local orig_table_concat  = table.concat
	local orig_tostring      = tostring
	local orig_tonumber      = tonumber
	local orig_bit32_bxor    = bit32.bxor
	local orig_Instance_new  = Instance.new

	-- ─── string.char — основной вектор сборки строк обфускаторами ───
	local charBuffer: {string} = {}
	local charBufferTimer: thread? = nil

	local function flushCharBuffer()
		if #charBuffer > 0 then
			local assembled = table.concat(charBuffer)
			charBuffer = {}
			if #assembled >= SPY_STRING_MIN_LEN then
				spyAddString(assembled)
			end
		end
		charBufferTimer = nil
	end

	pcall(function()
		local hooked_char = function(...: any): string
			local result = orig_string_char(...)
			-- Буферизуем посимвольные вызовы (обфускаторы часто делают string.char(x) в цикле)
			local args = table.pack(...)
			if args.n == 1 then
				charBuffer[#charBuffer + 1] = result
				-- Сбрасываем буфер через короткую задержку
				if not charBufferTimer then
					charBufferTimer = task.delay(0.05, flushCharBuffer)
				end
			else
				-- Многосимвольный вызов — сразу логируем
				flushCharBuffer()
				spyAddString(result)
			end
			return result
		end

		if hookfunction_fn then
			(hookfunction_fn :: any)(string.char, hooked_char)
		else
			-- Фоллбэк: подмена через debug
			pcall(function()
				(string :: any).char = hooked_char
			end)
		end
		originals.string_char = orig_string_char
	end)

	-- ─── table.concat — второй основной вектор сборки строк ───
	pcall(function()
		local hooked_concat = function(t: any, sep: any?, i: any?, j: any?): string
			local result = orig_table_concat(t, sep :: any, i :: any, j :: any)
			if #result >= SPY_STRING_MIN_LEN then
				spyAddString(result)
			end
			return result
		end

		if hookfunction_fn then
			(hookfunction_fn :: any)(table.concat, hooked_concat)
		else
			pcall(function()
				(table :: any).concat = hooked_concat
			end)
		end
		originals.table_concat = orig_table_concat
	end)

	-- ─── string.sub — часто используется для нарезки дешифрованных строк ───
	pcall(function()
		local sub_results: {string} = {}
		local sub_timer: thread? = nil
		local sub_count = 0

		local function flushSubResults()
			if #sub_results > 3 then
				local assembled = table.concat(sub_results)
				if #assembled >= SPY_STRING_MIN_LEN then
					spyAddString(assembled)
				end
			end
			sub_results = {}
			sub_count = 0
			sub_timer = nil
		end

		local hooked_sub = function(s: any, i: any, j: any?): string
			local result = orig_string_sub(s, i, j :: any)
			-- Если вызывается часто с i==1 j==1 или длина 1 — это посимвольная нарезка
			if type(i) == "number" and (j == nil or j == i) then
				sub_count += 1
				sub_results[#sub_results + 1] = result
				if not sub_timer then
					sub_timer = task.delay(0.05, flushSubResults)
				end
			elseif #result >= SPY_STRING_MIN_LEN then
				spyAddString(result)
			end
			return result
		end

		if hookfunction_fn then
			(hookfunction_fn :: any)(string.sub, hooked_sub)
		else
			pcall(function()
				(string :: any).sub = hooked_sub
			end)
		end
		originals.string_sub = orig_string_sub
	end)

	-- ─── string.reverse — иногда используется как финальный шаг деобфускации ───
	pcall(function()
		local hooked_reverse = function(s: any): string
			local result = orig_string_reverse(s)
			if #result >= SPY_STRING_MIN_LEN then
				spyAddString(result)
			end
			return result
		end

		if hookfunction_fn then
			(hookfunction_fn :: any)(string.reverse, hooked_reverse)
		else
			pcall(function()
				(string :: any).reverse = hooked_reverse
			end)
		end
		originals.string_reverse = orig_string_reverse
	end)

	-- ─── string.gsub — паттерн-замена, используется для финальной расшифровки ───
	pcall(function()
		local hooked_gsub = function(s: any, pattern: any, repl: any, n: any?): (string, number)
			local result, count = orig_string_gsub(s, pattern, repl, n :: any)
			if type(result) == "string" and #result >= SPY_STRING_MIN_LEN and count > 0 then
				spyAddString(result)
			end
			return result, count
		end

		if hookfunction_fn then
			(hookfunction_fn :: any)(string.gsub, hooked_gsub)
		else
			pcall(function()
				(string :: any).gsub = hooked_gsub
			end)
		end
		originals.string_gsub = orig_string_gsub
	end)

	-- ─── Instance.new — ловим создание объектов ───
	pcall(function()
		local hooked_new = function(className: any, parent: any?): any
			local result = orig_Instance_new(className, parent :: any)
			spyAdd("INSTANCE", "Instance.new(\"" .. tostring(className) .. "\"" ..
				(parent and (", " .. tostring(parent)) or "") .. ")")
			spyInstances[#spyInstances + 1] = tostring(className)
			return result
		end

		if hookfunction_fn then
			(hookfunction_fn :: any)(Instance.new, hooked_new)
		else
			pcall(function()
				(Instance :: any).new = hooked_new
			end)
		end
		originals.Instance_new = orig_Instance_new
	end)

	-- ─── __namecall шпион (GetService, FireServer, InvokeServer, Clone, etc.) ───
	-- Этот хук добавляется ПОВЕРХ существующего __namecall хука для HttpGet
	-- Используем отдельную таблицу методов для логирования
	local spyMethods: {[string]: string} = {
		-- Сеть
		FireServer     = "REMOTE",
		InvokeServer   = "REMOTE",
		FireClient     = "REMOTE",
		InvokeClient   = "REMOTE",
		FireAllClients = "REMOTE",
		-- Поиск
		GetService     = "SERVICE",
		FindFirstChild = "FIND",
		FindFirstChildOfClass = "FIND",
		FindFirstChildWhichIsA = "FIND",
		FindFirstDescendant = "FIND",
		WaitForChild   = "FIND",
		-- Данные
		GetAsync       = "DATASTORE",
		SetAsync       = "DATASTORE",
		UpdateAsync    = "DATASTORE",
		-- Другое
		Clone          = "CLONE",
		Destroy        = "DESTROY",
		TeleportAsync  = "TELEPORT",
		Kick           = "KICK",
	}

	if hookmetamethod_fn and getnamecallmethod_fn then
		pcall(function()
			local oldNc: any
			oldNc = (hookmetamethod_fn :: any)(game, "__namecall", function(self: any, ...: any): any
				local method = (getnamecallmethod_fn :: any)()
				local category = spyMethods[method]

				if category and spyActive then
					local args = table.pack(...)
					local argStrs: {string} = {}
					for i = 1, math.min(args.n, 6) do
						local v = args[i]
						local t = typeof(v)
						if t == "string" then
							local sv = (#v > 120) and (v:sub(1, 120) .. "…") or v
							argStrs[#argStrs + 1] = string.format("%q", sv:gsub("%c", " "))
						elseif t == "Instance" then
							argStrs[#argStrs + 1] = tostring(v)
						elseif t == "number" or t == "boolean" then
							argStrs[#argStrs + 1] = tostring(v)
						elseif t == "table" then
							-- Пробуем сериализовать маленькие таблицы
							local parts: {string} = {}
							local count = 0
							for k, val in pairs(v) do
								count += 1
								if count > 8 then
									parts[#parts + 1] = "..."
									break
								end
								local valStr = (typeof(val) == "string") and string.format("%q", val:sub(1,60):gsub("%c"," ")) or tostring(val)
								parts[#parts + 1] = tostring(k) .. "=" .. valStr
							end
							argStrs[#argStrs + 1] = "{" .. table.concat(parts, ", ") .. "}"
						elseif t == "Vector3" or t == "CFrame" or t == "Color3" or t == "UDim2" then
							argStrs[#argStrs + 1] = tostring(v)
						else
							argStrs[#argStrs + 1] = "<" .. t .. ">"
						end
					end

					local selfName = tostring(self)
					local logMsg = selfName .. ":" .. method .. "(" .. table.concat(argStrs, ", ") .. ")"
					spyAdd(category, logMsg)

					-- Специальные действия по категории
					if category == "REMOTE" then
						spyRemotes[#spyRemotes + 1] = logMsg
					elseif category == "SERVICE" and args.n >= 1 and typeof(args[1]) == "string" then
						spyServices[args[1]] = true
					elseif category == "TELEPORT" then
						spyAdd("WARNING", "!!! СКРИПТ ПЫТАЕТСЯ ТЕЛЕПОРТИРОВАТЬ !!!")
					elseif category == "KICK" then
						spyAdd("WARNING", "!!! СКРИПТ ПЫТАЕТСЯ КИКНУТЬ !!!")
					end

					-- Для строковых аргументов — добавляем в пул строк
					for i = 1, args.n do
						if typeof(args[i]) == "string" and #args[i] >= SPY_STRING_MIN_LEN then
							spyAddString(args[i])
						end
					end
				end

				-- ─── Перехват HttpGet/GetObjects (из v2) ───
				if HOOK_HTTPGET and hookActive.httpget
					and (method == "HttpGet" or method == "HttpGetAsync") then
					local args2 = table.pack(...)
					local url = tostring(args2[1])
					local results = table.pack(oldNc(self, ...))
					if typeof(results[1]) == "string" and #results[1] > 0 then
						task.spawn(function()
							httpCount += 1
							local fname = "http_" .. httpCount .. "_" .. sanitizeFilename(url) .. ".lua"
							saveFile(SESSION .. "/" .. fname, "-- URL: " .. url .. "\n-- Method: " .. method .. "\n-- Length: " .. #results[1] .. "\n\n" .. results[1])
							print("[Grabber] HTTP → " .. fname)
							-- Если похоже на код — дампим
							if results[1]:find("function", 1, true) or results[1]:find("local ", 1, true) then
								local origLs = originals.loadstring or genv.loadstring
								if typeof(origLs) == "function" then
									local okC, fn, err = pcall(origLs, results[1], url)
									if okC and typeof(fn) == "function" then
										saveDump("http:" .. url, results[1], fn, nil)
									end
								end
							end
						end)
						if checkCaptureLimit() then unhookAll() end
					end
					return table.unpack(results, 1, results.n)
				end

				if HOOK_GETOBJECTS and hookActive.getobjects and method == "GetObjects" then
					local args2 = table.pack(...)
					local url = tostring(args2[1])
					local results = table.pack(oldNc(self, ...))
					if typeof(results[1]) == "table" then
						task.spawn(function()
							for _, obj in ipairs(results[1]) do
								if typeof(obj) == "Instance" then
									if obj:IsA("LocalScript") or obj:IsA("ModuleScript") or obj:IsA("Script") then
										dumpScriptInstance(obj, "GetObjects:" .. url .. "/" .. obj.Name)
									end
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

				return oldNc(self, ...)
			end)
		end)

		if HOOK_HTTPGET then hookActive.httpget = true end
		if HOOK_GETOBJECTS then hookActive.getobjects = true end
	end

	-- ─── __index шпион (чтение свойств) ───
	-- Ловим обращения к .Text, .Value, .Source и другим интересным свойствам
	-- НЕ хукаем — слишком шумно и может сломать производительность.
	-- Вместо этого хукаем конкретные паттерны через getgenv callbacks.

	-- ─── Хук на setclipboard (некоторые скрипты воруют данные) ───
	for _, clipName in ipairs({"setclipboard", "toclipboard"}) do
		if typeof(genv[clipName]) == "function" then
			local origClip = genv[clipName]
			originals[clipName] = origClip
			pcall(function()
				genv[clipName] = function(content: any, ...): any
					spyAdd("CLIPBOARD", "setclipboard: " .. tostring(content):sub(1, 500))
					return origClip(content, ...)
				end
			end)
		end
	end

	-- ─── Хук на getgenv/getrenv/getfenv (скрипты проверяют окружение) ───
	-- Не хукаем — может сломать антитампер

	spyAdd("SYSTEM", "Runtime spy initialized")
end

-- ═══════════════════════════════════════════════════════════════════════════
-- РАСКРЫТИЕ ESCAPE-СТРОК В ИСХОДНИКЕ
-- ═══════════════════════════════════════════════════════════════════════════
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

local function unescapeSource(src: string): string
	if type(src) ~= "string" or #src == 0 then return src end
	if #src > MAX_CLEAN_SIZE then
		return "-- (исходник " .. #src .. " символов — слишком большой, смотри script.txt)"
	end

	local out: {string} = {}
	local i = 1
	local n = #src

	while i <= n do
		local b = src:byte(i)

		-- Комментарии
		if b == 45 and i < n and src:byte(i + 1) == 45 then
			local eqStart = i + 2
			if eqStart <= n and src:byte(eqStart) == 91 then
				local eqCount = 0
				local j = eqStart + 1
				while j <= n and src:byte(j) == 61 do
					eqCount += 1
					j += 1
				end
				if j <= n and src:byte(j) == 91 then
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

		-- Long strings [[...]]
		if b == 91 then
			local eqCount = 0
			local j = i + 1
			while j <= n and src:byte(j) == 61 do
				eqCount += 1
				j += 1
			end
			if j <= n and src:byte(j) == 91 then
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

		-- Строковые литералы "..." и '...'
		if b == 34 or b == 39 then
			local quote = b
			local j = i + 1
			local bodyParts: {string} = {}
			local closed = false

			while j <= n do
				local cb = src:byte(j)
				if cb == 92 then
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
				elseif cb == 10 or cb == 13 then
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
					local safeQuote = string.char(quote)
					if decoded:find(safeQuote, 1, true) then
						if not decoded:find("]]", 1, true) then
							out[#out + 1] = "[[" .. decoded .. "]]"
						elseif not decoded:find("]=]", 1, true) then
							out[#out + 1] = "[=[" .. decoded .. "]=]"
						else
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
				out[#out + 1] = src:sub(i, j)
				i = j + 1
			end

			if i > 0 and (i % YIELD_INTERVAL) < 128 then pcall(task.wait) end
			continue
		end

		out[#out + 1] = src:sub(i, i)
		i += 1
	end

	return table.concat(out)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- HEX DUMP БАЙТКОДА
-- ═══════════════════════════════════════════════════════════════════════════
local function bytecodeHexDump(bc: string): string
	local lines: {string} = {}
	lines[#lines + 1] = "-- RAW BYTECODE HEX DUMP"
	lines[#lines + 1] = "-- Длина: " .. #bc .. " байт"
	lines[#lines + 1] = "-- Для офлайн-декомпиляции: unluau / Luau Decompiler"
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
		if (offset % (64 * 1024)) == 0 and offset > 0 then pcall(task.wait) end
	end

	if limit < #bc then
		lines[#lines + 1] = ""
		lines[#lines + 1] = "-- (обрезано: " .. limit .. " из " .. #bc .. " байт)"
	end

	return table.concat(lines, "\n")
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ДАМП ФУНКЦИЙ
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
		if #s > 400 then s = s:sub(1, 400) .. "…" end
		return string.format("%q", s)
	elseif t == "number" then return tostring(v)
	elseif t == "boolean" then return tostring(v)
	elseif t == "nil" then return "nil"
	elseif t == "table" then return "<table>"
	elseif t == "function" then return "<function>"
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
		pcall(function() info = (dbg_getinfo :: any)(fn) or {} end)
	end

	local pad = string.rep("  ", depth)
	addFuncLine(string.format(
		"%s%s = function(...)  -- [%s] L%s..%s what=%s params=%s",
		pad, name,
		tostring(info.short_src or info.source or "?"),
		tostring(info.linedefined or 0),
		tostring(info.lastlinedefined or 0),
		tostring(info.what or "?"),
		tostring(info.nparams or "?")
	))

	if getupvalues_fn then
		local ok, uvs = pcall(getupvalues_fn :: any, fn)
		if ok and type(uvs) == "table" then
			local count = 0
			for idx, uv in pairs(uvs) do
				count += 1
				if count > 50 then
					addFuncLine(pad .. "  (ещё upvalue обрезано)")
					break
				end
				addFuncLine(pad .. "  upvalue[" .. tostring(idx) .. "] = " .. prettyValue(uv))
			end
		end
	end

	if getconstants_fn then
		local ok, consts = pcall(getconstants_fn :: any, fn)
		if ok and type(consts) == "table" then
			local parts: {string} = {}
			for i, c in ipairs(consts) do
				if i > 200 then
					parts[#parts + 1] = "… (ещё " .. (#consts - 200) .. ")"
					break
				end
				parts[#parts + 1] = prettyValue(c)
			end
			if #parts > 0 then
				addFuncLine(pad .. "  constants (" .. #consts .. "): " .. table.concat(parts, ", "))
			end
		end
	end

	if getprotos_fn then
		local ok, protos = pcall(getprotos_fn :: any, fn)
		if ok and type(protos) == "table" then
			local dumped = 0
			for i, proto in ipairs(protos) do
				if dumped >= MAX_PROTOS then
					addFuncLine(pad .. "  … (" .. dumped .. " из " .. #protos .. " прото)")
					break
				end
				if typeof(proto) == "function" then
					dumped += 1
					local okR, errR = pcall(dumpClosureRecursive, proto, name .. ".proto" .. i, depth + 1, srcLen)
					if not okR then
						addFuncLine(pad .. "  (ошибка proto" .. i .. ": " .. tostring(errR) .. ")")
					end
					if (dumped % 30) == 0 then pcall(task.wait) end
				end
			end
		end
	end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ИЗВЛЕЧЕНИЕ ВСЕХ СТРОКОВЫХ КОНСТАНТ ИЗ ЗАМЫКАНИЯ (РЕКУРСИВНО)
-- ═══════════════════════════════════════════════════════════════════════════
-- Обфускаторы хранят все строки в таблице констант корневой функции.
-- Извлекаем ВСЕ строки из всех уровней прото и сохраняем отдельным файлом.
local function extractAllStrings(fn: any): {string}
	local strings: {string} = {}
	local seen: {[any]: boolean} = {}

	local function walk(f: any, depth: number)
		if depth > 20 then return end
		if seen[f] then return end
		seen[f] = true

		-- Константы
		if getconstants_fn then
			local ok, consts = pcall(getconstants_fn :: any, f)
			if ok and type(consts) == "table" then
				for _, c in ipairs(consts) do
					if type(c) == "string" and #c >= 2 then
						strings[#strings + 1] = c
					end
				end
			end
		end

		-- Upvalues
		if getupvalues_fn then
			local ok, uvs = pcall(getupvalues_fn :: any, f)
			if ok and type(uvs) == "table" then
				for _, uv in pairs(uvs) do
					if type(uv) == "string" and #uv >= 2 then
						strings[#strings + 1] = uv
					elseif type(uv) == "table" then
						-- Таблица строк — частый паттерн обфускаторов
						for _, item in pairs(uv) do
							if type(item) == "string" and #item >= 2 then
								strings[#strings + 1] = item
							end
						end
					end
				end
			end
		end

		-- Прото-функции
		if getprotos_fn then
			local ok, protos = pcall(getprotos_fn :: any, f)
			if ok and type(protos) == "table" then
				for _, proto in ipairs(protos) do
					if typeof(proto) == "function" then
						walk(proto, depth + 1)
					end
				end
				if (#protos % 20) == 0 then pcall(task.wait) end
			end
		end
	end

	walk(fn, 0)

	-- Фильтруем и дедуплицируем
	local unique: {[string]: boolean} = {}
	local result: {string} = {}
	for _, s in ipairs(strings) do
		if not unique[s] then
			unique[s] = true
			-- Фильтруем бинарный мусор
			local printable = 0
			local checkLen = math.min(#s, 100)
			for ci = 1, checkLen do
				local byte = s:byte(ci)
				if (byte >= 32 and byte <= 126) or byte == 10 or byte == 13 or byte == 9 or byte > 127 then
					printable += 1
				end
			end
			if printable >= checkLen * 0.5 then
				result[#result + 1] = s
			end
		end
	end

	return result
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ОСНОВНОЙ ДАМП СКРИПТА
-- ═══════════════════════════════════════════════════════════════════════════
-- forward declaration needed for cross-reference
local saveDump: (chunkName: string?, source: string?, fn: any, errText: string?) -> ()
local dumpScriptInstance: (inst: Instance, label: string) -> ()

saveDump = function(chunkName: string?, source: string?, fn: any, errText: string?)
	dumpCount += 1
	local folder = SESSION .. "/dump_" .. dumpCount
	ensureDir(folder)

	local srcLen = (type(source) == "string") and #source or 0

	-- 1. Исходник
	saveFile(folder .. "/script.txt", table.concat({
		"-- ══ ScriptGrabber v3 ══",
		"-- chunk: " .. tostring(chunkName or "loadstring"),
		"-- source length: " .. srcLen .. " chars",
		"-- capture #" .. dumpCount,
		"",
		tostring(source or "(исходник недоступен)"),
	}, "\n"))

	-- 2. Раскрытые строки
	if type(source) == "string" and srcLen > 0 then
		local okClean, cleanResult = pcall(unescapeSource, source)
		if okClean and type(cleanResult) == "string" then
			saveFile(folder .. "/script_clean.txt", cleanResult)
		end
	end

	-- 3. Дамп функций
	funcDumpLines = {"=== Дамп функций: " .. tostring(chunkName or "loadstring") .. " ==="}
	funcDumpLineCount = 1
	if errText then addFuncLine("(!) Ошибка: " .. errText) end

	if fn then
		if srcLen <= MAX_FUNCDUMP_SRC then
			local okDump, errDump = pcall(dumpClosureRecursive, fn, "chunk", 0, srcLen)
			if not okDump then addFuncLine("(прерван: " .. tostring(errDump) .. ")") end
		else
			addFuncLine("(исходник " .. srcLen .. " символов — слишком большой)")
		end
	else
		addFuncLine("(функция не создана)")
	end
	saveFile(folder .. "/functions.txt", table.concat(funcDumpLines, "\n", 1, funcDumpLineCount))

	-- 4. НОВОЕ: Все строковые константы из замыкания → strings.txt
	if fn then
		local okStr, allStrings = pcall(extractAllStrings, fn)
		if okStr and type(allStrings) == "table" and #allStrings > 0 then
			local strLines: {string} = {
				"-- ═══ ВСЕ СТРОКИ ИЗ ЗАМЫКАНИЯ (" .. #allStrings .. " шт.) ═══",
				"-- Это ВСЕ строковые константы из всех уровней прото-функций.",
				"-- Обфускаторы хранят здесь исходные строки (имена переменных,",
				"-- вызовы API, URL, ключи и т.д.).",
				"",
			}
			for i, s in ipairs(allStrings) do
				strLines[#strLines + 1] = string.format("[%d] %s", i, s:gsub("%c", " "))
			end
			saveFile(folder .. "/strings.txt", table.concat(strLines, "\n"))
			print("[Grabber] Извлечено " .. #allStrings .. " строк из замыкания")
		end
	end

	-- 5. Декомпиляция
	if fn and decompile_fn and srcLen <= MAX_DECOMP_SIZE then
		local ok, res = pcall(decompile_fn :: any, fn)
		if ok and type(res) == "string" and #res > 0 then
			saveFile(folder .. "/decompiled.txt", res)
		else
			saveFile(folder .. "/decompiled.txt",
				"-- decompile() ошибка: " .. tostring(res))
			if getscriptbytecode_fn then
				local okBc, bc = pcall(getscriptbytecode_fn :: any, fn)
				if okBc and type(bc) == "string" then
					saveFile(folder .. "/bytecode_hex.txt", bytecodeHexDump(bc))
				end
			end
		end
	elseif fn and not decompile_fn then
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
			"-- decompile() отсутствует.",
			bcDumped and "-- Байткод: bytecode_hex.txt / bytecode_raw.bin" or "-- getscriptbytecode тоже нет.",
			"-- Для офлайн-декомпиляции: unluau / Luau Decompiler",
		}, "\n"))
	end

	-- 6. Мета
	if type(source) == "string" and srcLen > 0 then
		local hash: number = 2166136261
		local len = math.min(srcLen, 8192)
		for ci = 1, len do
			hash = bit32.bxor(hash, source:byte(ci))
			hash = bit32.band(hash * 16777619, 0xFFFFFFFF)
		end
		saveFile(folder .. "/meta.txt", table.concat({
			"chunk=" .. tostring(chunkName or "loadstring"),
			"source_len=" .. srcLen,
			"source_hash=" .. string.format("%08X", hash),
			"capture=" .. dumpCount,
		}, "\n"))
	end

	print("[Grabber] Перехват #" .. dumpCount .. " → " .. folder)
	notify("Grabber", "#" .. dumpCount .. " saved", 3)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ДАМП СКРИПТОВ ИЗ INSTANCE
-- ═══════════════════════════════════════════════════════════════════════════
dumpScriptInstance = function(inst: Instance, label: string)
	dumpCount += 1
	local safeName = sanitizeFilename(inst.Name)
	local folder = SESSION .. "/instance_" .. dumpCount .. "_" .. safeName
	ensureDir(folder)

	local okSrc, src = pcall(function() return (inst :: any).Source end)
	if okSrc and type(src) == "string" and #src > 0 then
		saveFile(folder .. "/script.txt", src)
		local okClean, clean = pcall(unescapeSource, src)
		if okClean and type(clean) == "string" then
			saveFile(folder .. "/script_clean.txt", clean)
		end
	else
		saveFile(folder .. "/script.txt", "-- Source недоступен")
	end

	if getscriptbytecode_fn then
		local okBc, bc = pcall(getscriptbytecode_fn :: any, inst)
		if okBc and type(bc) == "string" and #bc > 0 then
			saveFile(folder .. "/bytecode_raw.bin", bc)
			saveFile(folder .. "/bytecode_hex.txt", bytecodeHexDump(bc))
		end
	end

	if decompile_fn then
		local okDec, dec = pcall(decompile_fn :: any, inst)
		if okDec and type(dec) == "string" and #dec > 0 then
			saveFile(folder .. "/decompiled.txt", dec)
		else
			if okSrc and type(src) == "string" then
				local okDec2, dec2 = pcall(decompile_fn :: any, src)
				if okDec2 and type(dec2) == "string" then
					saveFile(folder .. "/decompiled.txt", dec2)
				end
			end
		end
	end

	saveFile(folder .. "/meta.txt", table.concat({
		"instance=" .. inst.Name,
		"class=" .. inst.ClassName,
		"path=" .. label,
		"capture=" .. dumpCount,
	}, "\n"))

	print("[Grabber] Instance → " .. label)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ХУКИ ЗАГРУЗКИ
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

	-- Сигнатура для фильтрации самого себя
	local selfSignature = "__SCRIPT_GRABBER_V3"

	local wrapped = function(src: any, chunkname: any, ...): any
		local results = table.pack(original(src, chunkname, ...))

		-- Фильтр: не перехватываем самого себя
		if type(src) == "string" and src:find(selfSignature, 1, true) then
			return table.unpack(results, 1, results.n)
		end

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
						task.spawn(function()
							httpCount += 1
							local fname = "http_" .. httpCount .. "_" .. sanitizeFilename(opts.Url) .. ".lua"
							saveFile(SESSION .. "/" .. fname, "-- URL: " .. opts.Url .. "\n-- Via: " .. name .. "\n\n" .. results[1].Body)
							-- Если похоже на код — дополнительный дамп
							local body = results[1].Body
							if body:find("function", 1, true) or body:find("local ", 1, true) then
								local origLs = originals.loadstring or genv.loadstring
								if typeof(origLs) == "function" then
									local okC, fn2, err2 = pcall(origLs, body, opts.Url)
									if okC and typeof(fn2) == "function" then
										saveDump("http:" .. opts.Url, body, fn2, nil)
									end
								end
							end
						end)
						if checkCaptureLimit() then unhookAll() end
					end

					return table.unpack(results, 1, results.n)
				end
				hookActive.request = true
			end)
		end
	end
end

-- ─── require ───
local function installRequireHook()
	if not HOOK_REQUIRE then return end
	local original = genv.require
	if typeof(original) ~= "function" then return end
	originals.require_hook = original

	local wrapped = function(target: any, ...: any): any
		local results = table.pack(original(target, ...))

		if typeof(target) == "number" then
			task.spawn(function()
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
	end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- СБРОС РАНТАЙМ-ЛОГА НА ДИСК
-- ═══════════════════════════════════════════════════════════════════════════
local function flushSpyLog()
	if spyCount == 0 then return end

	-- Основной лог
	saveFile(SESSION .. "/runtime_spy.txt", table.concat(spyLog, "\n", 1, spyCount))

	-- Уникальные строки (самое полезное для деобфускации)
	local strList: {string} = {}
	for s, _ in pairs(spyStrings) do
		strList[#strList + 1] = s:gsub("%c", " ")
	end
	table.sort(strList, function(a, b) return #a > #b end) -- длинные первыми
	if #strList > 0 then
		local strLines: {string} = {
			"-- ═══ СТРОКИ СОБРАННЫЕ В РАНТАЙМЕ (" .. #strList .. " шт.) ═══",
			"-- Это строки которые обфусцированный скрипт собирал через",
			"-- string.char, table.concat, string.sub, string.reverse и т.д.",
			"-- Здесь находятся РЕАЛЬНЫЕ строки после расшифровки.",
			"",
		}
		for i, s in ipairs(strList) do
			strLines[#strLines + 1] = string.format("[%d] (%d chars) %s", i, #s, s)
		end
		saveFile(SESSION .. "/runtime_strings.txt", table.concat(strLines, "\n"))
	end

	-- Сетевые вызовы (RemoteEvent/Function)
	if #spyRemotes > 0 then
		local remoteLines: {string} = {
			"-- ═══ СЕТЕВЫЕ ВЫЗОВЫ (" .. #spyRemotes .. " шт.) ═══",
			"-- FireServer / InvokeServer / FireClient вызовы скрипта.",
			"-- Показывают что скрипт РЕАЛЬНО делает на сервере.",
			"",
		}
		for i, r in ipairs(spyRemotes) do
			remoteLines[#remoteLines + 1] = string.format("[%d] %s", i, r)
		end
		saveFile(SESSION .. "/runtime_remotes.txt", table.concat(remoteLines, "\n"))
	end

	-- Использованные сервисы
	local svcList: {string} = {}
	for svc, _ in pairs(spyServices) do
		svcList[#svcList + 1] = svc
	end
	if #svcList > 0 then
		table.sort(svcList)
		saveFile(SESSION .. "/runtime_services.txt",
			"-- Сервисы которые скрипт использовал:\n" .. table.concat(svcList, "\n"))
	end

	-- Созданные инстансы
	if #spyInstances > 0 then
		local instCount: {[string]: number} = {}
		for _, cls in ipairs(spyInstances) do
			instCount[cls] = (instCount[cls] or 0) + 1
		end
		local instLines: {string} = {"-- Созданные Instance:", ""}
		for cls, cnt in pairs(instCount) do
			instLines[#instLines + 1] = cls .. " x" .. cnt
		end
		saveFile(SESSION .. "/runtime_instances.txt", table.concat(instLines, "\n"))
	end
end

-- Периодический сброс + сброс при выходе
task.spawn(function()
	while genv.__SCRIPT_GRABBER_V3 do
		task.wait(10)
		pcall(flushSpyLog)
	end
end)

-- ═══════════════════════════════════════════════════════════════════════════
-- БОНУСНЫЕ УТИЛИТЫ
-- ═══════════════════════════════════════════════════════════════════════════
genv.DumpGameScript = function(inst: any)
	if typeof(inst) ~= "Instance" then
		warn("[Grabber] DumpGameScript: передай Instance")
		return
	end
	pcall(dumpScriptInstance, inst, "manual:" .. inst:GetFullName())
end

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
	print("[Grabber] Дампнуто " .. count .. " скриптов")
	notify("Grabber", count .. " scripts dumped", 5)
end

-- Ручной сброс шпион-лога
genv.FlushSpyLog = function()
	pcall(flushSpyLog)
	print("[Grabber] Шпион-лог сброшен на диск")
end

-- Стоп
genv.StopGrabber = function()
	spyActive = false
	genv.__SCRIPT_GRABBER_V3 = nil
	pcall(flushSpyLog)
	pcall(unhookAll)
	-- Восстанавливаем string/table функции
	for _, key in ipairs({"string_char", "table_concat", "string_sub", "string_reverse", "string_gsub", "Instance_new"}) do
		if originals[key] then
			pcall(function()
				local lib, method = key:match("^(%w+)_(.+)$")
				if lib == "string" then
					(string :: any)[method] = originals[key]
				elseif lib == "table" then
					(table :: any)[method] = originals[key]
				elseif lib == "Instance" then
					(Instance :: any)[method] = originals[key]
				end
			end)
		end
	end
	print("[Grabber] Остановлен. Все хуки сняты.")
	notify("Grabber", "Остановлен", 3)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ИНИЦИАЛИЗАЦИЯ
-- ═══════════════════════════════════════════════════════════════════════════
ensureDir(ROOT)
ensureDir(SESSION)

saveFile(SESSION .. "/info.txt", table.concat({
	"ScriptGrabber v3 — " .. sessionName,
	"═══════════════════════════════",
	"Эксплойт: " .. tostring((typeof(identifyexecutor) == "function") and identifyexecutor() or "?"),
	"FS: " .. tostring(HAS_FS),
	"",
	"Возможности:",
	"  decompile:           " .. tostring(decompile_fn ~= nil),
	"  getscriptbytecode:   " .. tostring(getscriptbytecode_fn ~= nil),
	"  getconstants:        " .. tostring(getconstants_fn ~= nil),
	"  getupvalues:         " .. tostring(getupvalues_fn ~= nil),
	"  getprotos:           " .. tostring(getprotos_fn ~= nil),
	"  hookfunction:        " .. tostring(hookfunction_fn ~= nil),
	"  hookmetamethod:      " .. tostring(hookmetamethod_fn ~= nil),
	"",
	"РАНТАЙМ ШПИОН: " .. tostring(HOOK_RUNTIME_SPY),
	"  Хукает: string.char, table.concat, string.sub,",
	"          string.reverse, string.gsub, Instance.new,",
	"          FireServer, InvokeServer, GetService, setclipboard",
	"",
	"Результаты:",
	"  runtime_spy.txt      — полный лог всех API вызовов",
	"  runtime_strings.txt  — строки собранные в рантайме (после расшифровки)",
	"  runtime_remotes.txt  — все сетевые вызовы (FireServer и т.д.)",
	"  strings.txt          — строковые константы из замыкания",
	"  decompiled.txt       — декомпилированный код",
	"",
	"Утилиты:",
	"  DumpGameScript(inst)",
	"  DumpAllGameScripts(root?)",
	"  FlushSpyLog()        — сбросить лог на диск",
	"  StopGrabber()        — остановить и снять все хуки",
	"",
}, "\n"))

-- Устанавливаем хуки
installRuntimeSpy()      -- ПЕРВЫМ — чтобы ловить рантайм до loadstring
installLoadstringHook()
installRequestHook()
installRequireHook()
-- __namecall хук (HttpGet, GetObjects) установлен внутри installRuntimeSpy

local activeHooks: {string} = {}
for name, active in pairs(hookActive) do
	if active then activeHooks[#activeHooks + 1] = name end
end
if spyActive then activeHooks[#activeHooks + 1] = "runtime_spy" end

print("[Grabber] ══ v3 АКТИВЕН ══")
print("[Grabber] Хуки: " .. table.concat(activeHooks, ", "))
print("[Grabber] Рантайм шпион: " .. (spyActive and "ДА — ловлю string.char, table.concat, FireServer, Instance.new и т.д." or "НЕТ"))
print("[Grabber] Вывод: workspace/" .. SESSION)
notify("Grabber v3", "Активен! Рантайм шпион ON", 6)
