--[[═════════════════════════════════════════════════════════════════════════
    LURAPH TRACER — трассировка VM-обфусцированных скриптов
    ─────────────────────────────────────────────────────────────────────────
    Luraph / Ironbrew / Prometheus / и прочие VM-обфускаторы конвертируют
    исходник в кастомный байткод. decompile() видит только VM-диспатчер.

    ЭТОТ СКРИПТ работает по-другому:
      • Перехватывает ВСЕ реальные вызовы Roblox API во время выполнения
      • Скрипт может быть зашифрован как угодно — но в итоге ему надо
        вызвать game:GetService, Instance.new, :Connect, FireServer и т.д.
      • Мы логируем каждый такой вызов с аргументами
      • На выходе — ПОЛНЫЙ ЛИСТ того что скрипт ДЕЛАЕТ

    ПОРЯДОК:
      1) Запусти ЭТОТ скрипт
      2) Запусти обфусцированный скрипт (Luraph и т.п.)
      3) Подожди 5-15 секунд пока он отработает
      4) В чате напиши /dump — трассировка сохранится в файл
      5) Или она автосохраняется каждые 10 секунд

    ВЫХОД: workspace/LuraphTrace/<сессия>/
      trace.lua          — все API вызовы как читаемый Lua-псевдокод
      raw_log.txt        — полный лог с таймстампами
      strings.txt        — все строки которые скрипт расшифровал/использовал
      remotes.txt        — все FireServer / InvokeServer вызовы
      instances.txt      — все созданные Instance
      connections.txt    — все :Connect подключения
═══════════════════════════════════════════════════════════════════════════]]

local genv = getgenv and getgenv() or _G

if genv.__TRACER then
	warn("[Tracer] Уже активен")
	return
end
genv.__TRACER = true

---------------------------------------------------------------------------
-- FS
---------------------------------------------------------------------------
local hasFS = typeof(writefile) == "function"
local ROOT = "LuraphTrace"
local SESS do
	local ok, d = pcall(os.date, "%Y-%m-%d_%H-%M-%S")
	SESS = ROOT .. "/" .. (ok and d or tostring(math.floor(tick())))
end

local function dir(p)
	if not hasFS then return end
	pcall(function() if not isfolder(p) then makefolder(p) end end)
end
local function w(path, txt)
	if not hasFS then return end
	pcall(writefile, path, tostring(txt))
end
local function msg(t, tx)
	pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification",
			{Title=t, Text=tx, Duration=5})
	end)
end

dir(ROOT)
dir(SESS)

---------------------------------------------------------------------------
-- ЛОГ
---------------------------------------------------------------------------
local rawLog = {}       -- полный лог
local traceCode = {}    -- читаемый псевдокод
local capturedStrings = {} -- все строки
local remotes = {}      -- FireServer / InvokeServer
local instances = {}    -- Instance.new
local connections = {}  -- :Connect
local varCounter = 0
local instanceVars = {} -- Instance → имя переменной (для читаемости)
local startTime = tick()
local totalCalls = 0

local function ts()
	return string.format("[%.2f]", tick() - startTime)
end

-- Получить читаемое имя для значения
local function repr(v, depth)
	depth = depth or 0
	if depth > 2 then return "..." end
	local t = typeof(v)

	if t == "string" then
		-- Запоминаем строку
		if #v > 2 and not capturedStrings[v] then
			capturedStrings[v] = true
		end
		if #v > 100 then
			return '"' .. v:sub(1, 100):gsub('[%c\\"]', '.') .. '..."'
		end
		return '"' .. v:gsub('[%c\\"]', '.') .. '"'

	elseif t == "number" then
		return tostring(v)

	elseif t == "boolean" then
		return tostring(v)

	elseif t == "nil" then
		return "nil"

	elseif t == "Instance" then
		-- Даём переменную если ещё нет
		if not instanceVars[v] then
			local name = "unknown"
			pcall(function() name = v.Name end)
			local cls = "?"
			pcall(function() cls = v.ClassName end)
			instanceVars[v] = name .. "_" .. cls
		end
		local fullName = ""
		pcall(function() fullName = v:GetFullName() end)
		return fullName ~= "" and fullName or instanceVars[v]

	elseif t == "Vector3" or t == "Vector2" or t == "CFrame"
		or t == "Color3" or t == "UDim2" or t == "UDim"
		or t == "BrickColor" or t == "Enum" or t == "EnumItem" then
		return tostring(v)

	elseif t == "table" then
		local parts = {}
		local count = 0
		pcall(function()
			for k, val in pairs(v) do
				count = count + 1
				if count > 8 then parts[#parts+1] = "..."; break end
				if type(k) == "number" then
					parts[#parts+1] = repr(val, depth + 1)
				else
					parts[#parts+1] = tostring(k) .. "=" .. repr(val, depth + 1)
				end
			end
		end)
		return "{" .. table.concat(parts, ", ") .. "}"

	elseif t == "function" then
		return "<function>"

	elseif t == "RBXScriptSignal" then
		return "<Signal>"

	elseif t == "RBXScriptConnection" then
		return "<Connection>"
	end

	local ok, str = pcall(tostring, v)
	return ok and str or "<" .. t .. ">"
end

local function reprArgs(...)
	local args = table.pack(...)
	local parts = {}
	for i = 1, args.n do
		parts[i] = repr(args[i])
	end
	return table.concat(parts, ", ")
end

-- Логирование
local function log(category, codeLine, rawLine)
	totalCalls = totalCalls + 1
	rawLog[#rawLog+1] = ts() .. " " .. (rawLine or codeLine)
	if codeLine then
		traceCode[#traceCode+1] = codeLine
	end
	if category == "remote" then
		remotes[#remotes+1] = ts() .. " " .. (rawLine or codeLine)
	elseif category == "instance" then
		instances[#instances+1] = codeLine
	elseif category == "connect" then
		connections[#connections+1] = ts() .. " " .. codeLine
	end
end

---------------------------------------------------------------------------
-- ПЕРЕХВАТ __namecall (ВСЕ вызовы методов на всех Instance)
-- Это ГЛАВНЫЙ перехватчик — ловит всё что делает VM
---------------------------------------------------------------------------
if typeof(hookmetamethod) == "function" then
	pcall(function()
		local oldNC
		oldNC = hookmetamethod(game, "__namecall", function(self, ...)
			local method = getnamecallmethod()
			local args = table.pack(...)

			-- Не логируем наши собственные вызовы
			if typeof(checkcaller) == "function" then
				local ok, isSelf = pcall(checkcaller)
				if ok and isSelf then
					return oldNC(self, ...)
				end
			end

			local selfName = ""
			pcall(function() selfName = self:GetFullName() end)
			local cls = ""
			pcall(function() cls = self.ClassName end)

			local argsStr = reprArgs(...)

			-- ── КАТЕГОРИЗАЦИЯ ──────────────────────────────────────

			-- FireServer / InvokeServer — самое важное
			if method == "FireServer" or method == "InvokeServer"
				or method == "fireServer" or method == "invokeServer" then
				log("remote",
					selfName .. ":" .. method .. "(" .. argsStr .. ")",
					"[REMOTE] " .. selfName .. ":" .. method .. "(" .. argsStr .. ")")

			-- Connect — подписка на события
			elseif method == "Connect" or method == "connect"
				or method == "Once" or method == "once" then
				log("connect",
					selfName .. "." .. (args.n > 0 and "" or "Event") .. ":" .. method .. "(<callback>)",
					"[CONNECT] " .. selfName .. ":" .. method)

			-- HttpGet
			elseif method == "HttpGet" or method == "HttpGetAsync" then
				log("http",
					'game:' .. method .. '(' .. argsStr .. ')',
					"[HTTP] " .. method .. " " .. tostring(args[1] or ""))

			-- GetService
			elseif method == "GetService" then
				log("api",
					'game:GetService(' .. argsStr .. ')',
					"[SERVICE] " .. tostring(args[1] or ""))

			-- FindFirstChild / WaitForChild
			elseif method == "FindFirstChild" or method == "WaitForChild"
				or method == "FindFirstChildOfClass" or method == "FindFirstChildWhichIsA" then
				log("api",
					selfName .. ':' .. method .. '(' .. argsStr .. ')')

			-- Clone, Destroy, Remove
			elseif method == "Clone" or method == "Destroy" or method == "Remove"
				or method == "ClearAllChildren" then
				log("api",
					selfName .. ':' .. method .. '()')

			-- TweenService:Create
			elseif method == "Create" and cls == "TweenService" then
				log("api",
					'TweenService:Create(' .. argsStr .. ')')

			-- Play, Stop (для Tween, Sound, Animation)
			elseif method == "Play" or method == "Stop" or method == "Pause"
				or method == "Resume" or method == "AdjustSpeed" then
				log("api",
					selfName .. ':' .. method .. '(' .. argsStr .. ')')

			-- SetPrimaryPartCFrame / PivotTo
			elseif method == "SetPrimaryPartCFrame" or method == "PivotTo"
				or method == "MoveTo" or method == "TranslateBy" then
				log("api",
					selfName .. ':' .. method .. '(' .. argsStr .. ')')

			-- Kick
			elseif method == "Kick" then
				log("api",
					selfName .. ':Kick(' .. argsStr .. ')',
					"[KICK] " .. selfName .. " : " .. argsStr)

			-- Teleport
			elseif method == "Teleport" or method == "TeleportToPlaceInstance" then
				log("api",
					selfName .. ':' .. method .. '(' .. argsStr .. ')',
					"[TELEPORT] " .. argsStr)

			-- Всё остальное тоже логируем (но менее подробно)
			else
				-- Фильтруем шум: не логируем слишком частые вызовы
				if method ~= "IsA" and method ~= "IsDescendantOf"
					and method ~= "IsAncestorOf" and method ~= "GetPropertyChangedSignal"
					and method ~= "GetChildren" and method ~= "GetDescendants" then
					log("api",
						selfName .. ':' .. method .. '(' .. argsStr .. ')')
				end
			end

			return oldNC(self, ...)
		end)
	end)
	print("[Tracer] __namecall hook ✓ (ВСЕ вызовы методов)")
end

---------------------------------------------------------------------------
-- ПЕРЕХВАТ __newindex (запись свойств)
---------------------------------------------------------------------------
if typeof(hookmetamethod) == "function" then
	pcall(function()
		local oldNI
		oldNI = hookmetamethod(game, "__newindex", function(self, key, value)
			-- Не логируем свои вызовы
			if typeof(checkcaller) == "function" then
				local ok, isSelf = pcall(checkcaller)
				if ok and isSelf then
					return oldNI(self, key, value)
				end
			end

			local selfName = ""
			pcall(function() selfName = self:GetFullName() end)

			-- Важные свойства
			if type(key) == "string" then
				local val = repr(value)
				if key == "Parent" then
					log("api",
						selfName .. ".Parent = " .. val,
						"[PARENT] " .. selfName .. " → " .. val)
				elseif key == "CFrame" or key == "Position" or key == "Size"
					or key == "Transparency" or key == "Visible" or key == "Text"
					or key == "Value" or key == "Enabled" or key == "Name" then
					log("api", selfName .. "." .. key .. " = " .. val)
				end
			end

			return oldNI(self, key, value)
		end)
	end)
	print("[Tracer] __newindex hook ✓ (запись свойств)")
end

---------------------------------------------------------------------------
-- ПЕРЕХВАТ Instance.new
---------------------------------------------------------------------------
if typeof(hookfunction) == "function" then
	pcall(function()
		local origNew = Instance.new
		local oldNew
		oldNew = hookfunction(Instance.new, function(cls, parent, ...)
			local result = oldNew(cls, parent, ...)

			if typeof(checkcaller) == "function" then
				local ok, isSelf = pcall(checkcaller)
				if ok and isSelf then return result end
			end

			varCounter = varCounter + 1
			local varName = "v" .. varCounter
			local parentStr = ""
			if parent then
				pcall(function() parentStr = ", " .. parent:GetFullName() end)
			end
			instanceVars[result] = varName
			log("instance",
				"local " .. varName .. ' = Instance.new("' .. tostring(cls) .. '"' .. parentStr .. ')',
				"[NEW] " .. tostring(cls) .. parentStr)

			return result
		end)
	end)
	print("[Tracer] Instance.new hook ✓")
end

---------------------------------------------------------------------------
-- ПЕРЕХВАТ loadstring — ловим сам обфусцированный скрипт + внутренние
---------------------------------------------------------------------------
local origLS = genv.loadstring or loadstring
if typeof(origLS) == "function" then
	pcall(function()
		local hook = function(src, name)
			local fn, err = origLS(src, name)

			task.spawn(function()
				pcall(function()
					-- Сохраняем RAW
					if type(src) == "string" and #src > 0 then
						local idx = #rawLog
						w(SESS .. "/loadstring_" .. idx .. "_raw.lua",
							"-- chunk: " .. tostring(name or "?")
							.. "\n-- size: " .. #src .. "\n\n" .. src)
						print("[Tracer] loadstring перехвачен: " .. #src .. " chars")

						-- Пробуем decompile
						if typeof(decompile) == "function" and typeof(fn) == "function" then
							local ok, dec = pcall(decompile, fn)
							if ok and type(dec) == "string" and #dec > 5 then
								w(SESS .. "/loadstring_" .. idx .. "_decompiled.lua", dec)
								print("[Tracer] decompile OK: " .. #dec .. " chars")
							end
						end
					end

					log("api",
						'loadstring(<' .. (type(src) == "string" and #src or 0) .. ' chars>, '
						.. repr(name) .. ')')
				end)
			end)

			return fn, err
		end

		genv.loadstring = hook
		pcall(function() _G.loadstring = hook end)
	end)
	print("[Tracer] loadstring hook ✓")
end

---------------------------------------------------------------------------
-- ПЕРЕХВАТ HttpGet через хук (дополнительно к __namecall)
---------------------------------------------------------------------------
for _, rn in ipairs({"request", "http_request", "syn_request"}) do
	if typeof(genv[rn]) == "function" then
		local orig = genv[rn]
		pcall(function()
			genv[rn] = function(opts, ...)
				local res = {orig(opts, ...)}
				pcall(function()
					if type(opts) == "table" and type(opts.Url) == "string"
						and type(res[1]) == "table" and type(res[1].Body) == "string" then
						w(SESS .. "/request_" .. tostring(opts.Url):gsub("[^%w]","_"):sub(1,40) .. ".lua",
							"-- " .. opts.Url .. "\n\n" .. res[1].Body)
						log("http", rn .. '({Url="' .. opts.Url:sub(1,80) .. '", ...})')
					end
				end)
				return unpack(res)
			end
		end)
	end
end

---------------------------------------------------------------------------
-- СОХРАНЕНИЕ ТРАССИРОВКИ
---------------------------------------------------------------------------
local function saveTrace()
	if totalCalls == 0 then return end

	-- Основной псевдокод
	local header = table.concat({
		"-- ═══════════════════════════════════════════════════",
		"-- LURAPH TRACE — восстановленная логика скрипта",
		"-- Сессия: " .. SESS,
		"-- Всего API вызовов: " .. totalCalls,
		"-- Время трассировки: " .. string.format("%.1f", tick() - startTime) .. " сек",
		"-- ═══════════════════════════════════════════════════",
		"",
	}, "\n")
	w(SESS .. "/trace.lua", header .. table.concat(traceCode, "\n"))

	-- Полный лог
	w(SESS .. "/raw_log.txt", table.concat(rawLog, "\n"))

	-- Строки
	local strList = {}
	for s in pairs(capturedStrings) do
		if #s > 2 and #s < 5000 then strList[#strList+1] = s end
	end
	table.sort(strList, function(a, b) return #a > #b end)
	w(SESS .. "/strings.txt", table.concat(strList, "\n---\n"))

	-- Remote вызовы
	if #remotes > 0 then
		w(SESS .. "/remotes.txt", table.concat(remotes, "\n"))
	end

	-- Инстансы
	if #instances > 0 then
		w(SESS .. "/instances.txt", table.concat(instances, "\n"))
	end

	-- Коннекты
	if #connections > 0 then
		w(SESS .. "/connections.txt", table.concat(connections, "\n"))
	end

	print(("[Tracer] Сохранено: %d вызовов, %d строк → %s"):format(
		totalCalls, #strList, SESS))
end

-- Автосохранение каждые 10 секунд
task.spawn(function()
	while genv.__TRACER do
		task.wait(10)
		pcall(saveTrace)
	end
end)

-- Команда /dump в чате
pcall(function()
	local Players = game:GetService("Players")
	local lp = Players.LocalPlayer
	if lp then
		pcall(function()
			lp.Chatted:Connect(function(m)
				if m:lower() == "/dump" then
					pcall(saveTrace)
					msg("Tracer", "Трассировка сохранена! " .. totalCalls .. " вызовов")
				end
			end)
		end)
	end
end)

-- Сохранение при выходе
pcall(function()
	game:BindToClose(function()
		pcall(saveTrace)
	end)
end)

---------------------------------------------------------------------------
-- GC СКАН — дополнительно вытащить строки из памяти
---------------------------------------------------------------------------
task.delay(8, function()
	pcall(function()
		if typeof(getgc) ~= "function" then return end
		local objects = getgc()
		if type(objects) ~= "table" then return end

		local codeFragments = {}
		for _, obj in ipairs(objects) do
			if type(obj) == "string" and #obj > 30 and #obj < 50000 then
				-- Проверяем на код
				local n = 0
				for _, kw in ipairs({"function","local ","end","return","then","game","require"}) do
					if obj:find(kw, 1, true) then n = n + 1 end
				end
				if n >= 2 then
					codeFragments[#codeFragments+1] = obj
				end
			end
		end

		if #codeFragments > 0 then
			table.sort(codeFragments, function(a, b) return #a > #b end)
			local out = {"-- [Tracer] CODE FRAGMENTS FROM GC MEMORY", "-- Count: " .. #codeFragments, ""}
			for i, s in ipairs(codeFragments) do
				if i > 100 then break end
				out[#out+1] = "-- [" .. i .. "] len=" .. #s
				out[#out+1] = s
				out[#out+1] = ""
			end
			w(SESS .. "/gc_code.txt", table.concat(out, "\n"))
			print("[Tracer] GC scan: " .. #codeFragments .. " code fragments")
		end
	end)
end)

---------------------------------------------------------------------------
print("[Tracer] ══ ACTIVE ══ Запускай Luraph скрипт → workspace/" .. SESS)
print("[Tracer] Напиши /dump в чат чтобы сохранить трассировку")
msg("LuraphTracer", "ACTIVE! Запускай скрипт, потом /dump")
