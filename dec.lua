--!strict
--[[═══════════════════════════════════════════════════════════════════════════
    SCRIPT GRABBER v3.1 — ПЕРЕХВАТ + РАНТАЙМ ШПИОН (СТАБИЛЬНАЯ ВЕРСИЯ)
    ═══════════════════════════════════════════════════════════════════════════
    Уровень 1: Перехват загрузки (loadstring, HttpGet, request, require, GetObjects)
    Уровень 2: Раскрытие escape-строк (\xNN, \ddd, \u{}, \z)
    Уровень 3: Рантайм шпион — ловит что обфусцированный скрипт реально делает

    АНТИКРАШ:
      - Реентрантная защита (хуки не вызывают сами себя)
      - Внутри хуков используются ТОЛЬКО оригинальные функции
      - checkcaller() фильтрует вызовы Roblox-движка (логируем только эксплойт)

    Запуск: выполни ПЕРВЫМ, потом целевой скрипт.
    Результат: workspace/ScriptGrabber/<сессия>/
═══════════════════════════════════════════════════════════════════════════]]

local genv = (typeof(getgenv) == "function") and getgenv() or _G

if genv.__GRABBER_V31 then
	warn("[Grabber] Уже активен.")
	return
end
genv.__GRABBER_V31 = true

-- ═══════════════════════════════════════════════════════════════════════════
-- ОРИГИНАЛЫ — СОХРАНЯЕМ ДО ВСЕХ ХУКОВ
-- ═══════════════════════════════════════════════════════════════════════════
-- Все внутренние операции граббера используют ТОЛЬКО эти оригиналы.
-- Это предотвращает рекурсию когда хукнутые функции вызываются внутри хуков.
local O_string_char    = string.char
local O_string_byte    = string.byte
local O_string_sub     = string.sub
local O_string_find    = string.find
local O_string_format  = string.format
local O_string_gsub    = string.gsub
local O_string_rep     = string.rep
local O_string_reverse = string.reverse
local O_table_concat   = table.concat
local O_table_pack     = table.pack
local O_table_insert   = table.insert
local O_tostring       = tostring
local O_tonumber       = tonumber
local O_type           = type
local O_typeof         = typeof
local O_pcall          = pcall
local O_ipairs         = ipairs
local O_pairs          = pairs
local O_math_min       = math.min
local O_math_floor     = math.floor
local O_bit32_bxor     = bit32.bxor
local O_bit32_band     = bit32.band

-- ═══════════════════════════════════════════════════════════════════════════
-- НАСТРОЙКИ
-- ═══════════════════════════════════════════════════════════════════════════
local MAX_CAPTURES      = -1
local HOOK_LOADSTRING   = true
local HOOK_HTTPGET      = true
local HOOK_REQUEST      = true
local HOOK_REQUIRE      = true
local HOOK_GETOBJECTS   = true
local HOOK_RUNTIME_SPY  = true

local MAX_CLEAN_SIZE    = 1024 * 1024
local MAX_DECOMP_SIZE   = 1024 * 1024
local MAX_FUNCDUMP_SRC  = 2 * 1024 * 1024
local MAX_PROTOS        = 500
local MAX_FUNC_LINES    = 20000
local YIELD_INTERVAL    = 256 * 1024
local MAX_BYTECODE_HEX  = 512 * 1024
local MAX_SPY_LINES     = 30000
local SPY_STRING_MIN    = 4

-- ═══════════════════════════════════════════════════════════════════════════
-- ВОЗМОЖНОСТИ ЭКСПЛОЙТА
-- ═══════════════════════════════════════════════════════════════════════════
local HAS_FS = (O_typeof(writefile) == "function")
	and (O_typeof(isfolder) == "function")
	and (O_typeof(makefolder) == "function")

local dbg_getinfo      = (O_typeof(debug) == "table" and O_typeof(debug.getinfo) == "function") and debug.getinfo or nil
local getconstants_fn  = (O_typeof(getconstants) == "function") and getconstants or nil
local getupvalues_fn   = (O_typeof(getupvalues) == "function") and getupvalues or nil
local getprotos_fn     = (O_typeof(getprotos) == "function") and getprotos or nil
local decompile_fn     = (O_typeof(decompile) == "function") and decompile or nil
local getscriptbc_fn   = (O_typeof(getscriptbytecode) == "function") and getscriptbytecode or nil
local hookfunction_fn  = (O_typeof(hookfunction) == "function") and hookfunction or nil
local hookmetamethod_fn = (O_typeof(hookmetamethod) == "function") and hookmetamethod or nil
local getnamecall_fn   = (O_typeof(getnamecallmethod) == "function") and getnamecallmethod or nil
local checkcaller_fn   = (O_typeof(checkcaller) == "function") and checkcaller or nil

-- ═══════════════════════════════════════════════════════════════════════════
-- СЕССИЯ
-- ═══════════════════════════════════════════════════════════════════════════
local ROOT = "ScriptGrabber"
local sessionName: string
do
	local ok, stamp = O_pcall(os.date, "%Y-%m-%d_%H-%M-%S")
	sessionName = (ok and O_type(stamp) == "string") and (stamp :: string) or O_tostring(O_math_floor(tick()))
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
-- РЕЕНТРАНТНАЯ ЗАЩИТА
-- ═══════════════════════════════════════════════════════════════════════════
-- Единственный флаг. Если true — мы внутри хука, все хуки пропускают логику.
local IN_HOOK = false

-- ═══════════════════════════════════════════════════════════════════════════
-- УТИЛИТЫ (используют ТОЛЬКО оригиналы)
-- ═══════════════════════════════════════════════════════════════════════════
local function notify(title: string, text: string, dur: number?)
	O_pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification", {
			Title = title,
			Text = text,
			Duration = dur or 4,
		})
	end)
end

local function ensureDir(path: string)
	if not HAS_FS then return end
	if not isfolder(path) then O_pcall(makefolder, path) end
end

local function saveFile(path: string, content: string)
	if not HAS_FS then
		warn("[Grabber] FS недоступна: " .. path)
		print(O_tostring(content))
		return
	end
	local ok, err = O_pcall(writefile, path, O_tostring(content))
	if not ok then
		warn("[Grabber] Ошибка: " .. O_tostring(err))
	end
end

local function sanitizeFN(s: string): string
	return O_string_gsub(O_tostring(s), "[^%w%.%-_]", "_"):sub(1, 60)
end

local function checkLimit(): boolean
	if MAX_CAPTURES < 0 then return false end
	totalCaptures += 1
	return totalCaptures >= MAX_CAPTURES
end

local function unhookAll()
	if hookActive.loadstring and originals.loadstring then
		O_pcall(function() genv.loadstring = originals.loadstring end)
		hookActive.loadstring = false
	end
	if hookActive.request then
		for _, name in O_ipairs({"request", "http_request"}) do
			if originals[name] then
				O_pcall(function() genv[name] = originals[name] end)
			end
		end
		hookActive.request = false
	end
	if hookActive.require_hook and originals.require_hook then
		O_pcall(function() genv.require = originals.require_hook end)
		hookActive.require_hook = false
	end
	hookActive.httpget = false
	hookActive.getobjects = false
end

-- ═══════════════════════════════════════════════════════════════════════════
-- РАНТАЙМ ШПИОН (БЕЗОПАСНАЯ ВЕРСИЯ)
-- ═══════════════════════════════════════════════════════════════════════════
-- Все операции внутри хуков используют O_ оригиналы → нет рекурсии.
-- checkcaller() фильтрует вызовы движка → меньше шума и нагрузки.

local spyLog: {string} = {}
local spyCount = 0
local spyStrings: {[string]: boolean} = {}
local spyRemotes: {string} = {}
local spyInstances: {string} = {}
local spyServices: {[string]: boolean} = {}
local spyActive = false

-- Добавить строку в лог (БЕЗ вызовов хукнутых функций)
local function spyRawAdd(cat: string, msg: string)
	if spyCount >= MAX_SPY_LINES then return end
	spyCount += 1
	-- Используем только оригиналы
	local ts = O_string_format("%.2f", tick() % 10000)
	spyLog[spyCount] = "[" .. ts .. "][" .. cat .. "] " .. msg
end

-- Добавить строку в пул уникальных строк
local function spyRawString(s: string)
	if #s < SPY_STRING_MIN or #s > 5000 then return end
	-- Проверяем что строка печатная (без рекурсивных вызовов)
	local printable = 0
	local check = O_math_min(#s, 100)
	for ci = 1, check do
		local byte = O_string_byte(s, ci)
		if (byte >= 32 and byte <= 126) or byte == 10 or byte == 9 or byte > 127 then
			printable += 1
		end
	end
	if printable < check * 0.5 then return end
	if spyStrings[s] then return end
	spyStrings[s] = true
	spyRawAdd("STR", O_string_sub(O_string_gsub(s, "%c", " "), 1, 500))
end

local function installRuntimeSpy()
	if not HOOK_RUNTIME_SPY then return end
	if not hookfunction_fn then
		warn("[Grabber] hookfunction недоступен — рантайм шпион отключен")
		return
	end

	spyActive = true

	-- ─── string.char (основной вектор сборки строк обфускаторами) ───
	local charBuf: {number} = {}
	local charFlushScheduled = false

	local function flushCharBuf()
		charFlushScheduled = false
		if #charBuf == 0 then return end
		IN_HOOK = true
		local ok, assembled = O_pcall(O_string_char, table.unpack(charBuf))
		charBuf = {}
		if ok and O_type(assembled) == "string" then
			spyRawString(assembled :: string)
		end
		IN_HOOK = false
	end

	O_pcall(function()
		(hookfunction_fn :: any)(string.char, function(...: any): string
			local result = O_string_char(...)
			if IN_HOOK then return result end
			-- checkcaller: true = вызов из эксплойта, false = из движка
			if checkcaller_fn and not (checkcaller_fn :: any)() then return result end

			IN_HOOK = true
			local args = O_table_pack(...)
			if args.n == 1 and O_type(args[1]) == "number" then
				charBuf[#charBuf + 1] = args[1] :: number
				if not charFlushScheduled then
					charFlushScheduled = true
					task.delay(0.1, flushCharBuf)
				end
			elseif #result >= SPY_STRING_MIN then
				-- Многосимвольный вызов — сразу логируем
				flushCharBuf()
				spyRawString(result)
			end
			IN_HOOK = false
			return result
		end)
	end)

	-- ─── table.concat (второй основной вектор) ───
	O_pcall(function()
		(hookfunction_fn :: any)(table.concat, function(t: any, sep: any?, i: any?, j: any?): string
			local result = O_table_concat(t, sep :: any, i :: any, j :: any)
			if IN_HOOK then return result end
			if checkcaller_fn and not (checkcaller_fn :: any)() then return result end

			IN_HOOK = true
			if #result >= SPY_STRING_MIN then
				spyRawString(result)
			end
			IN_HOOK = false
			return result
		end)
	end)

	-- ─── string.reverse (финальный шаг некоторых обфускаторов) ───
	O_pcall(function()
		(hookfunction_fn :: any)(string.reverse, function(s: any): string
			local result = O_string_reverse(s)
			if IN_HOOK then return result end
			if checkcaller_fn and not (checkcaller_fn :: any)() then return result end

			IN_HOOK = true
			if #result >= SPY_STRING_MIN then
				spyRawString(result)
			end
			IN_HOOK = false
			return result
		end)
	end)

	-- ─── setclipboard (воровство данных) ───
	for _, clipName in O_ipairs({"setclipboard", "toclipboard"}) do
		if O_typeof(genv[clipName]) == "function" then
			local origClip = genv[clipName]
			originals[clipName] = origClip
			O_pcall(function()
				genv[clipName] = function(content: any, ...): any
					if not IN_HOOK then
						IN_HOOK = true
						spyRawAdd("CLIPBOARD", O_string_sub(O_tostring(content), 1, 500))
						IN_HOOK = false
					end
					return origClip(content, ...)
				end
			end)
		end
	end

	-- ─── __namecall шпион (FireServer, InvokeServer, GetService + HttpGet/GetObjects) ───
	if hookmetamethod_fn and getnamecall_fn then
		local spyMethods: {[string]: string} = {
			FireServer     = "REMOTE",
			InvokeServer   = "REMOTE",
			FireClient     = "REMOTE",
			InvokeClient   = "REMOTE",
			FireAllClients = "REMOTE",
			GetService     = "SERVICE",
			FindFirstChild = "FIND",
			WaitForChild   = "FIND",
			GetAsync       = "DATA",
			SetAsync       = "DATA",
			UpdateAsync    = "DATA",
			TeleportAsync  = "TELEPORT",
			Kick           = "KICK",
		}

		O_pcall(function()
			local oldNc: any
			oldNc = (hookmetamethod_fn :: any)(game, "__namecall", function(self: any, ...: any): any
				local method = (getnamecall_fn :: any)()

				-- ─── Шпион (только если не в рекурсии) ───
				if not IN_HOOK and spyActive then
					local cat = spyMethods[method]
					if cat then
						IN_HOOK = true
						local args = O_table_pack(...)
						local argParts: {string} = {}
						for ai = 1, O_math_min(args.n, 5) do
							local v = args[ai]
							local t = O_typeof(v)
							if t == "string" then
								local sv = (#(v :: string) > 80) and O_string_sub(v :: string, 1, 80) .. "…" or (v :: string)
								argParts[#argParts + 1] = '"' .. O_string_gsub(sv, "%c", " ") .. '"'
							elseif t == "number" or t == "boolean" then
								argParts[#argParts + 1] = O_tostring(v)
							elseif t == "Instance" then
								argParts[#argParts + 1] = O_tostring(v)
							elseif t == "table" then
								local tParts: {string} = {}
								local tc = 0
								for k, val in O_pairs(v :: any) do
									tc += 1
									if tc > 6 then
										tParts[#tParts + 1] = "..."
										break
									end
									local vs = (O_typeof(val) == "string")
										and ('"' .. O_string_sub(O_string_gsub(val :: string, "%c", " "), 1, 40) .. '"')
										or O_tostring(val)
									tParts[#tParts + 1] = O_tostring(k) .. "=" .. vs
								end
								argParts[#argParts + 1] = "{" .. O_table_concat(tParts, ",") .. "}"
							else
								argParts[#argParts + 1] = "<" .. t .. ">"
							end
						end

						local logMsg = O_tostring(self) .. ":" .. method .. "(" .. O_table_concat(argParts, ", ") .. ")"
						spyRawAdd(cat, logMsg)

						if cat == "REMOTE" then
							spyRemotes[#spyRemotes + 1] = logMsg
						elseif cat == "SERVICE" and args.n >= 1 and O_typeof(args[1]) == "string" then
							spyServices[args[1] :: string] = true
						elseif cat == "TELEPORT" then
							spyRawAdd("WARN", "ТЕЛЕПОРТ!")
						elseif cat == "KICK" then
							spyRawAdd("WARN", "КИК!")
						end

						-- Строковые аргументы в пул
						for ai = 1, args.n do
							if O_typeof(args[ai]) == "string" and #(args[ai] :: string) >= SPY_STRING_MIN then
								spyRawString(args[ai] :: string)
							end
						end

						IN_HOOK = false
					end
				end

				-- ─── HttpGet перехват ───
				if HOOK_HTTPGET and hookActive.httpget
					and (method == "HttpGet" or method == "HttpGetAsync") then
					local args = O_table_pack(...)
					local url = O_tostring(args[1])
					local results = O_table_pack(oldNc(self, ...))
					if O_typeof(results[1]) == "string" and #(results[1] :: string) > 0 then
						task.spawn(function()
							IN_HOOK = true
							httpCount += 1
							local fname = "http_" .. httpCount .. "_" .. sanitizeFN(url) .. ".lua"
							saveFile(SESSION .. "/" .. fname,
								"-- URL: " .. url .. "\n-- Method: " .. method ..
								"\n-- Length: " .. #(results[1] :: string) .. "\n\n" .. (results[1] :: string))

							local body = results[1] :: string
							if O_string_find(body, "function", 1, true) or O_string_find(body, "local ", 1, true) then
								local origLs = originals.loadstring or genv.loadstring
								if O_typeof(origLs) == "function" then
									local okC, fn2, err2 = O_pcall(origLs, body, url)
									if okC and O_typeof(fn2) == "function" then
										IN_HOOK = false
										saveDump("http:" .. url, body, fn2, nil)
										IN_HOOK = true
									end
								end
							end
							IN_HOOK = false
						end)
						if checkLimit() then unhookAll() end
					end
					return table.unpack(results, 1, results.n)
				end

				-- ─── GetObjects перехват ───
				if HOOK_GETOBJECTS and hookActive.getobjects and method == "GetObjects" then
					local args = O_table_pack(...)
					local url = O_tostring(args[1])
					local results = O_table_pack(oldNc(self, ...))
					if O_typeof(results[1]) == "table" then
						task.spawn(function()
							IN_HOOK = true
							for _, obj in O_ipairs(results[1] :: any) do
								if O_typeof(obj) == "Instance" then
									local inst = obj :: Instance
									if inst:IsA("LocalScript") or inst:IsA("ModuleScript") or inst:IsA("Script") then
										IN_HOOK = false
										dumpScriptInstance(inst, "GetObjects:" .. url .. "/" .. inst.Name)
										IN_HOOK = true
									end
									for _, desc in O_ipairs(inst:GetDescendants()) do
										if O_typeof(desc) == "Instance"
											and (desc:IsA("LocalScript") or desc:IsA("ModuleScript") or desc:IsA("Script")) then
											IN_HOOK = false
											dumpScriptInstance(desc, "GetObjects:" .. url .. "/" .. desc:GetFullName())
											IN_HOOK = true
										end
									end
								end
							end
							IN_HOOK = false
						end)
						if checkLimit() then unhookAll() end
					end
					return table.unpack(results, 1, results.n)
				end

				return oldNc(self, ...)
			end)
		end)

		if HOOK_HTTPGET then hookActive.httpget = true end
		if HOOK_GETOBJECTS then hookActive.getobjects = true end
	end

	spyRawAdd("SYS", "Runtime spy initialized")
end

-- ═══════════════════════════════════════════════════════════════════════════
-- РАСКРЫТИЕ ESCAPE-СТРОК
-- ═══════════════════════════════════════════════════════════════════════════
local function decodeBody(body: string): string?
	if not O_string_find(body, "\\", 1, true) then return nil end
	local s = O_string_gsub(body, "\\z%s+", "")
	s = O_string_gsub(s, "\\u%{(%x+)%}", function(hex: string): string
		local cp = O_tonumber(hex, 16) or 0xFFFD
		local ok, ch = O_pcall(utf8.char, cp)
		return (ok and ch) or "?"
	end)
	s = O_string_gsub(s, "\\x(%x%x)", function(h: string): string
		return O_string_char(O_tonumber(h, 16) or 63)
	end)
	s = O_string_gsub(s, "\\(%d%d?%d?)", function(d: string): string
		local num = O_tonumber(d)
		if num and num < 256 then return O_string_char(num) end
		return "\\" .. d
	end)
	s = O_string_gsub(s, "\\a", "\a")
	s = O_string_gsub(s, "\\b", "\b")
	s = O_string_gsub(s, "\\f", "\f")
	s = O_string_gsub(s, "\\n", "\n")
	s = O_string_gsub(s, "\\r", "\r")
	s = O_string_gsub(s, "\\t", "\t")
	s = O_string_gsub(s, "\\v", "\v")
	s = O_string_gsub(s, "\\\\", "\\")
	s = O_string_gsub(s, "\\'", "'")
	s = O_string_gsub(s, '\\"', '"')
	if s == body then return nil end
	return s
end

local function unescapeSource(src: string): string
	if O_type(src) ~= "string" or #src == 0 then return src end
	if #src > MAX_CLEAN_SIZE then return "-- (слишком большой: " .. #src .. ", смотри script.txt)" end

	local out: {string} = {}
	local i = 1
	local n = #src

	while i <= n do
		local b = O_string_byte(src, i)

		if b == 45 and i < n and O_string_byte(src, i + 1) == 45 then
			local eqStart = i + 2
			if eqStart <= n and O_string_byte(src, eqStart) == 91 then
				local eqCount = 0
				local j = eqStart + 1
				while j <= n and O_string_byte(src, j) == 61 do eqCount += 1; j += 1 end
				if j <= n and O_string_byte(src, j) == 91 then
					local cp = "]" .. O_string_rep("=", eqCount) .. "]"
					local pos = O_string_find(src, cp, j + 1, true)
					if pos then
						out[#out + 1] = O_string_sub(src, i, pos + #cp - 1)
						i = pos + #cp
					else
						out[#out + 1] = O_string_sub(src, i)
						i = n + 1
					end
					continue
				end
			end
			local nl = O_string_find(src, "\n", i, true)
			if nl then
				out[#out + 1] = O_string_sub(src, i, nl)
				i = nl + 1
			else
				out[#out + 1] = O_string_sub(src, i)
				i = n + 1
			end
			continue
		end

		if b == 91 then
			local eqCount = 0
			local j = i + 1
			while j <= n and O_string_byte(src, j) == 61 do eqCount += 1; j += 1 end
			if j <= n and O_string_byte(src, j) == 91 then
				local cp = "]" .. O_string_rep("=", eqCount) .. "]"
				local pos = O_string_find(src, cp, j + 1, true)
				if pos then
					out[#out + 1] = O_string_sub(src, i, pos + #cp - 1)
					i = pos + #cp
				else
					out[#out + 1] = O_string_sub(src, i)
					i = n + 1
				end
				continue
			end
		end

		if b == 34 or b == 39 then
			local quote = b
			local j = i + 1
			local bodyParts: {string} = {}
			local closed = false
			while j <= n do
				local cb = O_string_byte(src, j)
				if cb == 92 then
					if j + 1 <= n then
						bodyParts[#bodyParts + 1] = O_string_sub(src, j, j + 1)
						j += 2
					else
						bodyParts[#bodyParts + 1] = O_string_sub(src, j, j)
						j += 1
					end
				elseif cb == quote then
					closed = true
					break
				elseif cb == 10 or cb == 13 then
					break
				else
					bodyParts[#bodyParts + 1] = O_string_sub(src, j, j)
					j += 1
				end
			end
			if closed then
				local rawBody = O_table_concat(bodyParts)
				local decoded = decodeBody(rawBody)
				if decoded then
					local q = O_string_char(quote)
					if O_string_find(decoded, q, 1, true) then
						if not O_string_find(decoded, "]]", 1, true) then
							out[#out + 1] = "[[" .. decoded .. "]]"
						elseif not O_string_find(decoded, "]=]", 1, true) then
							out[#out + 1] = "[=[" .. decoded .. "]=]"
						else
							out[#out + 1] = O_string_sub(src, i, j)
						end
					else
						out[#out + 1] = q .. decoded .. q
					end
				else
					out[#out + 1] = O_string_sub(src, i, j)
				end
				i = j + 1
			else
				out[#out + 1] = O_string_sub(src, i, j)
				i = j + 1
			end
			if i > 0 and (i % YIELD_INTERVAL) < 128 then O_pcall(task.wait) end
			continue
		end

		out[#out + 1] = O_string_sub(src, i, i)
		i += 1
	end

	return O_table_concat(out)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- HEX DUMP
-- ═══════════════════════════════════════════════════════════════════════════
local function hexDump(bc: string): string
	local lines: {string} = {"-- RAW BYTECODE HEX DUMP", "-- " .. #bc .. " bytes", ""}
	local limit = O_math_min(#bc, MAX_BYTECODE_HEX)
	for offset = 0, limit - 1, 16 do
		local hex: {string} = {}
		local ascii: {string} = {}
		for col = 0, 15 do
			local pos = offset + col + 1
			if pos > limit then
				hex[#hex + 1] = "  "
				ascii[#ascii + 1] = " "
			else
				local byte = O_string_byte(bc, pos)
				hex[#hex + 1] = O_string_format("%02X", byte)
				ascii[#ascii + 1] = (byte >= 32 and byte <= 126) and O_string_char(byte) or "."
			end
		end
		lines[#lines + 1] = O_string_format("%08X  %s  |%s|", offset, O_table_concat(hex, " "), O_table_concat(ascii))
		if (offset % (64 * 1024)) == 0 and offset > 0 then O_pcall(task.wait) end
	end
	if limit < #bc then lines[#lines + 1] = "\n-- (обрезано: " .. limit .. "/" .. #bc .. ")" end
	return O_table_concat(lines, "\n")
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ДАМП ФУНКЦИЙ
-- ═══════════════════════════════════════════════════════════════════════════
local fLines: {string} = {}
local fCount = 0

local function fAdd(s: string)
	if fCount < MAX_FUNC_LINES then fCount += 1; fLines[fCount] = s end
end

local function pVal(v: any): string
	local t = O_typeof(v)
	if t == "string" then
		local s = O_string_gsub(O_tostring(v), "%c", " ")
		if #s > 300 then s = O_string_sub(s, 1, 300) .. "…" end
		return O_string_format("%q", s)
	elseif t == "number" or t == "boolean" or t == "nil" then return O_tostring(v)
	elseif t == "table" then return "<table>"
	elseif t == "function" then return "<func>"
	elseif t == "Instance" then
		local ok, cls = O_pcall(function() return v.ClassName end)
		return "<" .. (ok and O_tostring(cls) or "Instance") .. ">"
	end
	return "<" .. t .. ">"
end

local function dumpClosure(fn: any, name: string, depth: number, srcLen: number)
	if depth > 25 or srcLen > MAX_FUNCDUMP_SRC then return end
	local info: {[string]: any} = {}
	if dbg_getinfo then O_pcall(function() info = (dbg_getinfo :: any)(fn) or {} end) end
	local pad = O_string_rep("  ", depth)
	fAdd(O_string_format("%s%s = func  -- [%s] L%s..%s params=%s",
		pad, name,
		O_tostring(info.short_src or "?"),
		O_tostring(info.linedefined or 0),
		O_tostring(info.lastlinedefined or 0),
		O_tostring(info.nparams or "?")))

	if getupvalues_fn then
		local ok, uvs = O_pcall(getupvalues_fn :: any, fn)
		if ok and O_type(uvs) == "table" then
			local c = 0
			for idx, uv in O_pairs(uvs) do
				c += 1
				if c > 40 then fAdd(pad .. "  (ещё upvalue…)"); break end
				fAdd(pad .. "  uv[" .. O_tostring(idx) .. "]=" .. pVal(uv))
			end
		end
	end

	if getconstants_fn then
		local ok, consts = O_pcall(getconstants_fn :: any, fn)
		if ok and O_type(consts) == "table" and #consts > 0 then
			local parts: {string} = {}
			for i, c in O_ipairs(consts) do
				if i > 150 then parts[#parts + 1] = "…(+" .. (#consts - 150) .. ")"; break end
				parts[#parts + 1] = pVal(c)
			end
			fAdd(pad .. "  const(" .. #consts .. "): " .. O_table_concat(parts, ", "))
		end
	end

	if getprotos_fn then
		local ok, protos = O_pcall(getprotos_fn :: any, fn)
		if ok and O_type(protos) == "table" then
			local d = 0
			for i, proto in O_ipairs(protos) do
				if d >= MAX_PROTOS then break end
				if O_typeof(proto) == "function" then
					d += 1
					O_pcall(dumpClosure, proto, name .. ".p" .. i, depth + 1, srcLen)
					if (d % 25) == 0 then O_pcall(task.wait) end
				end
			end
		end
	end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ИЗВЛЕЧЕНИЕ ВСЕХ СТРОК ИЗ ЗАМЫКАНИЯ
-- ═══════════════════════════════════════════════════════════════════════════
local function extractStrings(fn: any): {string}
	local strings: {string} = {}
	local seen: {[any]: boolean} = {}

	local function walk(f: any, depth: number)
		if depth > 20 or seen[f] then return end
		seen[f] = true

		if getconstants_fn then
			local ok, consts = O_pcall(getconstants_fn :: any, f)
			if ok and O_type(consts) == "table" then
				for _, c in O_ipairs(consts) do
					if O_type(c) == "string" and #c >= 2 then
						strings[#strings + 1] = c
					end
				end
			end
		end

		if getupvalues_fn then
			local ok, uvs = O_pcall(getupvalues_fn :: any, f)
			if ok and O_type(uvs) == "table" then
				for _, uv in O_pairs(uvs) do
					if O_type(uv) == "string" and #uv >= 2 then
						strings[#strings + 1] = uv
					elseif O_type(uv) == "table" then
						for _, item in O_pairs(uv) do
							if O_type(item) == "string" and #item >= 2 then
								strings[#strings + 1] = item
							end
						end
					end
				end
			end
		end

		if getprotos_fn then
			local ok, protos = O_pcall(getprotos_fn :: any, f)
			if ok and O_type(protos) == "table" then
				for _, proto in O_ipairs(protos) do
					if O_typeof(proto) == "function" then
						walk(proto, depth + 1)
					end
				end
			end
		end
	end

	walk(fn, 0)

	-- Дедупликация + фильтр мусора
	local unique: {[string]: boolean} = {}
	local result: {string} = {}
	for _, s in O_ipairs(strings) do
		if not unique[s] then
			unique[s] = true
			local printable = 0
			local cl = O_math_min(#s, 80)
			for ci = 1, cl do
				local byte = O_string_byte(s, ci)
				if (byte >= 32 and byte <= 126) or byte == 10 or byte == 9 or byte > 127 then
					printable += 1
				end
			end
			if printable >= cl * 0.4 then
				result[#result + 1] = s
			end
		end
	end
	return result
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ОСНОВНОЙ ДАМП
-- ═══════════════════════════════════════════════════════════════════════════
local saveDump: (chunkName: string?, source: string?, fn: any, errText: string?) -> ()
local dumpScriptInstance: (inst: Instance, label: string) -> ()

saveDump = function(chunkName: string?, source: string?, fn: any, errText: string?)
	dumpCount += 1
	local folder = SESSION .. "/dump_" .. dumpCount
	ensureDir(folder)
	local srcLen = (O_type(source) == "string") and #(source :: string) or 0

	-- 1. Исходник
	saveFile(folder .. "/script.txt", O_table_concat({
		"-- ScriptGrabber v3.1",
		"-- chunk: " .. O_tostring(chunkName or "loadstring"),
		"-- length: " .. srcLen,
		"-- capture #" .. dumpCount,
		"",
		O_tostring(source or "(нет исходника)"),
	}, "\n"))

	-- 2. Clean
	if O_type(source) == "string" and srcLen > 0 then
		local okC, clean = O_pcall(unescapeSource, source :: string)
		if okC and O_type(clean) == "string" then saveFile(folder .. "/script_clean.txt", clean :: string) end
	end

	-- 3. Функции
	fLines = {"=== Дамп: " .. O_tostring(chunkName or "loadstring") .. " ==="}
	fCount = 1
	if errText then fAdd("ERR: " .. errText) end
	if fn then
		if srcLen <= MAX_FUNCDUMP_SRC then
			O_pcall(dumpClosure, fn, "chunk", 0, srcLen)
		else
			fAdd("(слишком большой: " .. srcLen .. ")")
		end
	end
	saveFile(folder .. "/functions.txt", O_table_concat(fLines, "\n", 1, fCount))

	-- 4. Строки из замыкания
	if fn then
		local okS, allStr = O_pcall(extractStrings, fn)
		if okS and O_type(allStr) == "table" and #allStr > 0 then
			local sLines: {string} = {
				"-- ВСЕ СТРОКИ ИЗ ЗАМЫКАНИЯ (" .. #allStr .. ")",
				"-- Константы и upvalue из всех proto-функций.",
				"-- Обфускаторы хранят здесь API имена, URL, ключи.",
				"",
			}
			for i, s in O_ipairs(allStr) do
				sLines[#sLines + 1] = "[" .. i .. "] " .. O_string_gsub(s, "%c", " ")
			end
			saveFile(folder .. "/strings.txt", O_table_concat(sLines, "\n"))
		end
	end

	-- 5. Декомпиляция
	if fn and decompile_fn and srcLen <= MAX_DECOMP_SIZE then
		local ok, res = O_pcall(decompile_fn :: any, fn)
		if ok and O_type(res) == "string" and #(res :: string) > 0 then
			saveFile(folder .. "/decompiled.txt", res :: string)
		else
			saveFile(folder .. "/decompiled.txt", "-- decompile ошибка: " .. O_tostring(res))
		end
	elseif fn and not decompile_fn then
		if getscriptbc_fn then
			local okB, bc = O_pcall(getscriptbc_fn :: any, fn)
			if okB and O_type(bc) == "string" and #(bc :: string) > 0 then
				saveFile(folder .. "/bytecode_hex.txt", hexDump(bc :: string))
				saveFile(folder .. "/bytecode_raw.bin", bc :: string)
			end
		end
		saveFile(folder .. "/decompiled.txt", "-- decompile() отсутствует, байткод в bytecode_*.txt")
	end

	-- 6. Meta
	if O_type(source) == "string" and srcLen > 0 then
		local hash: number = 2166136261
		local hl = O_math_min(srcLen, 8192)
		for ci = 1, hl do
			hash = O_bit32_bxor(hash, O_string_byte(source :: string, ci))
			hash = O_bit32_band(hash * 16777619, 0xFFFFFFFF)
		end
		saveFile(folder .. "/meta.txt", O_table_concat({
			"chunk=" .. O_tostring(chunkName or "loadstring"),
			"len=" .. srcLen,
			"hash=" .. O_string_format("%08X", hash),
			"n=" .. dumpCount,
		}, "\n"))
	end

	print("[Grabber] #" .. dumpCount .. " → " .. folder)
	notify("Grabber", "#" .. dumpCount .. " saved", 3)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ДАМП INSTANCE
-- ═══════════════════════════════════════════════════════════════════════════
dumpScriptInstance = function(inst: Instance, label: string)
	dumpCount += 1
	local folder = SESSION .. "/inst_" .. dumpCount .. "_" .. sanitizeFN(inst.Name)
	ensureDir(folder)

	local okSrc, src = O_pcall(function() return (inst :: any).Source end)
	if okSrc and O_type(src) == "string" and #src > 0 then
		saveFile(folder .. "/script.txt", src)
		local okC, clean = O_pcall(unescapeSource, src)
		if okC and O_type(clean) == "string" then saveFile(folder .. "/script_clean.txt", clean :: string) end
	else
		saveFile(folder .. "/script.txt", "-- Source недоступен")
	end

	if getscriptbc_fn then
		local okB, bc = O_pcall(getscriptbc_fn :: any, inst)
		if okB and O_type(bc) == "string" and #bc > 0 then
			saveFile(folder .. "/bytecode_raw.bin", bc)
			saveFile(folder .. "/bytecode_hex.txt", hexDump(bc))
		end
	end

	if decompile_fn then
		local okD, dec = O_pcall(decompile_fn :: any, inst)
		if okD and O_type(dec) == "string" and #dec > 0 then
			saveFile(folder .. "/decompiled.txt", dec)
		end
	end

	saveFile(folder .. "/meta.txt", O_table_concat({
		"name=" .. inst.Name, "class=" .. inst.ClassName, "path=" .. label, "n=" .. dumpCount,
	}, "\n"))
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ХУКИ ЗАГРУЗКИ
-- ═══════════════════════════════════════════════════════════════════════════
local SELF_SIG = "__GRABBER_V31"

local function installLoadstringHook()
	if not HOOK_LOADSTRING then return end
	local original = genv.loadstring
	if O_typeof(original) ~= "function" then return end
	originals.loadstring = original

	local wrapped = function(src: any, chunkname: any, ...): any
		local results = O_table_pack(original(src, chunkname, ...))
		-- Не ловим самих себя
		if O_type(src) == "string" and O_string_find(src :: string, SELF_SIG, 1, true) then
			return table.unpack(results, 1, results.n)
		end
		local fn = (O_typeof(results[1]) == "function") and results[1] or nil
		local err = (fn == nil and results.n >= 2) and O_tostring(results[2]) or nil
		task.spawn(saveDump, chunkname, src, fn, err)
		if checkLimit() and hookActive.loadstring then unhookAll() end
		return table.unpack(results, 1, results.n)
	end

	local okSet = O_pcall(function() genv.loadstring = wrapped end)
	if okSet then
		hookActive.loadstring = true
	elseif hookfunction_fn then
		O_pcall(function()
			(hookfunction_fn :: any)(original, wrapped)
			hookActive.loadstring = true
		end)
	end
end

local function installRequestHook()
	if not HOOK_REQUEST then return end
	for _, name in O_ipairs({"request", "http_request"}) do
		local original = genv[name]
		if O_typeof(original) == "function" then
			originals[name] = original
			O_pcall(function()
				genv[name] = function(opts: any, ...: any): any
					local results = O_table_pack(original(opts, ...))
					if O_typeof(opts) == "table" and O_typeof(opts.Url) == "string"
						and O_typeof(results[1]) == "table" and O_typeof(results[1].Body) == "string"
						and #results[1].Body > 0 then
						task.spawn(function()
							httpCount += 1
							local fname = "http_" .. httpCount .. "_" .. sanitizeFN(opts.Url) .. ".lua"
							saveFile(SESSION .. "/" .. fname, "-- URL: " .. opts.Url .. "\n\n" .. results[1].Body)
						end)
						if checkLimit() then unhookAll() end
					end
					return table.unpack(results, 1, results.n)
				end
				hookActive.request = true
			end)
		end
	end
end

local function installRequireHook()
	if not HOOK_REQUIRE then return end
	local original = genv.require
	if O_typeof(original) ~= "function" then return end
	originals.require_hook = original

	local wrapped = function(target: any, ...: any): any
		local results = O_table_pack(original(target, ...))
		if O_typeof(target) == "number" then
			task.spawn(function()
				local okI, model = O_pcall(function()
					return game:GetService("InsertService"):LoadAsset(target)
				end)
				if okI and O_typeof(model) == "Instance" then
					for _, desc in O_ipairs((model :: Instance):GetDescendants()) do
						if O_typeof(desc) == "Instance" and desc:IsA("ModuleScript") then
							dumpScriptInstance(desc, "require(" .. target .. ")/" .. desc:GetFullName())
						end
					end
					O_pcall(function() (model :: Instance):Destroy() end)
				end
			end)
		elseif O_typeof(target) == "Instance" and (target :: Instance):IsA("ModuleScript") then
			task.spawn(dumpScriptInstance, target :: Instance, "require:" .. (target :: Instance):GetFullName())
		end
		return table.unpack(results, 1, results.n)
	end

	local okSet = O_pcall(function() genv.require = wrapped end)
	if okSet then
		hookActive.require_hook = true
	elseif hookfunction_fn then
		O_pcall(function()
			(hookfunction_fn :: any)(original, wrapped)
			hookActive.require_hook = true
		end)
	end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- СБРОС РАНТАЙМ ЛОГА
-- ═══════════════════════════════════════════════════════════════════════════
local function flushSpy()
	if spyCount == 0 and next(spyStrings) == nil then return end
	IN_HOOK = true

	if spyCount > 0 then
		saveFile(SESSION .. "/runtime_spy.txt", O_table_concat(spyLog, "\n", 1, spyCount))
	end

	local strList: {string} = {}
	for s, _ in O_pairs(spyStrings) do
		strList[#strList + 1] = O_string_gsub(s, "%c", " ")
	end
	if #strList > 0 then
		table.sort(strList, function(a: string, b: string) return #a > #b end)
		local sLines: {string} = {
			"-- СТРОКИ СОБРАННЫЕ В РАНТАЙМЕ (" .. #strList .. ")",
			"-- Всё что скрипт собирал через string.char / table.concat / string.reverse",
			"-- Это РЕАЛЬНЫЕ строки после расшифровки обфускатором.",
			"",
		}
		for i, s in O_ipairs(strList) do
			sLines[#sLines + 1] = "[" .. i .. "] (" .. #s .. ") " .. s
		end
		saveFile(SESSION .. "/runtime_strings.txt", O_table_concat(sLines, "\n"))
	end

	if #spyRemotes > 0 then
		local rLines: {string} = {"-- СЕТЕВЫЕ ВЫЗОВЫ (" .. #spyRemotes .. ")", ""}
		for i, r in O_ipairs(spyRemotes) do
			rLines[#rLines + 1] = "[" .. i .. "] " .. r
		end
		saveFile(SESSION .. "/runtime_remotes.txt", O_table_concat(rLines, "\n"))
	end

	local svcList: {string} = {}
	for svc, _ in O_pairs(spyServices) do svcList[#svcList + 1] = svc end
	if #svcList > 0 then
		saveFile(SESSION .. "/runtime_services.txt", O_table_concat(svcList, "\n"))
	end

	IN_HOOK = false
end

-- Автосброс каждые 15 секунд
task.spawn(function()
	while genv.__GRABBER_V31 do
		task.wait(15)
		O_pcall(flushSpy)
	end
end)

-- ═══════════════════════════════════════════════════════════════════════════
-- УТИЛИТЫ ПОЛЬЗОВАТЕЛЯ
-- ═══════════════════════════════════════════════════════════════════════════
genv.DumpGameScript = function(inst: any)
	if O_typeof(inst) ~= "Instance" then warn("[Grabber] Передай Instance"); return end
	O_pcall(dumpScriptInstance, inst :: Instance, "manual:" .. (inst :: Instance):GetFullName())
end

genv.DumpAllGameScripts = function(root: any?)
	local r: Instance = (O_typeof(root) == "Instance") and (root :: Instance) or game
	local c = 0
	for _, desc in O_ipairs(r:GetDescendants()) do
		if O_typeof(desc) == "Instance"
			and (desc:IsA("LocalScript") or desc:IsA("ModuleScript") or desc:IsA("Script")) then
			c += 1
			O_pcall(dumpScriptInstance, desc, "bulk:" .. desc:GetFullName())
			if (c % 5) == 0 then O_pcall(task.wait) end
		end
	end
	print("[Grabber] " .. c .. " скриптов")
end

genv.FlushSpyLog = function()
	O_pcall(flushSpy)
	print("[Grabber] Лог сброшен")
end

genv.StopGrabber = function()
	spyActive = false
	genv.__GRABBER_V31 = nil
	O_pcall(flushSpy)
	O_pcall(unhookAll)
	print("[Grabber] Остановлен")
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ЗАПУСК
-- ═══════════════════════════════════════════════════════════════════════════
ensureDir(ROOT)
ensureDir(SESSION)

saveFile(SESSION .. "/info.txt", O_table_concat({
	"ScriptGrabber v3.1 — " .. sessionName,
	"══════════════════════════",
	"Executor: " .. O_tostring((O_typeof(identifyexecutor) == "function") and identifyexecutor() or "?"),
	"FS: " .. O_tostring(HAS_FS),
	"hookfunction: " .. O_tostring(hookfunction_fn ~= nil),
	"hookmetamethod: " .. O_tostring(hookmetamethod_fn ~= nil),
	"checkcaller: " .. O_tostring(checkcaller_fn ~= nil),
	"decompile: " .. O_tostring(decompile_fn ~= nil),
	"getscriptbytecode: " .. O_tostring(getscriptbc_fn ~= nil),
	"getconstants: " .. O_tostring(getconstants_fn ~= nil),
	"getupvalues: " .. O_tostring(getupvalues_fn ~= nil),
	"getprotos: " .. O_tostring(getprotos_fn ~= nil),
	"",
	"Runtime spy: " .. O_tostring(HOOK_RUNTIME_SPY),
	"Hooks: string.char, table.concat, string.reverse, __namecall",
	"",
	"Commands:",
	"  FlushSpyLog()         — сбросить лог",
	"  StopGrabber()         — остановить",
	"  DumpGameScript(inst)  — дамп скрипта игры",
	"  DumpAllGameScripts()  — дамп всех скриптов",
}, "\n"))

installRuntimeSpy()
installLoadstringHook()
installRequestHook()
installRequireHook()

local active: {string} = {}
for name, on in O_pairs(hookActive) do
	if on then active[#active + 1] = name end
end
if spyActive then active[#active + 1] = "runtime_spy" end

print("[Grabber] ══ v3.1 ACTIVE ══ " .. O_table_concat(active, ", "))
print("[Grabber] → workspace/" .. SESSION)
notify("Grabber v3.1", #active .. " hooks active", 5)
