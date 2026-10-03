--[[═════════════════════════════════════════════════════════════════════════
    RAM & EXECUTOR INSPECTOR (Диагностический скрипт)
    ─────────────────────────────────────────────────────────────────────────
    ИНСТРУКЦИЯ:
    1) Запусти этот скрипт первым.
    2) Запусти любой скрипт через loadstring.
    3) Все данные, пути в памяти, функции и проверка API выведутся в консоль 
       и сохранятся в workspace/inspector_log.txt.
    4) Скопируй вывод или содержимое inspector_log.txt и отправь мне.
═══════════════════════════════════════════════════════════════════════════]]

local genv = (typeof(getgenv) == "function") and getgenv() or _G

if genv.__INSPECTOR_ACTIVE then
	warn("[Inspector] Уже активен в памяти.")
	return
end
genv.__INSPECTOR_ACTIVE = true

local HAS_FS = (typeof(writefile) == "function")
local LOG_FILE = "inspector_log.txt"
local logBuffer = {}

local function out(msg)
	local text = tostring(msg)
	print("[Inspector] " .. text)
	if typeof(rconsoleprint) == "function" then
		pcall(rconsoleprint, "[Inspector] " .. text .. "\n")
	end
	table.insert(logBuffer, text)
	if HAS_FS then
		pcall(writefile, LOG_FILE, table.concat(logBuffer, "\n"))
	end
end

out("==================================================")
out("           RAM & EXECUTOR DIAGNOSTIC LOG         ")
out("==================================================")
out("Время запуска: " .. os.date("%Y-%m-%d %H:%M:%S"))

-- 1. Проверка окружения эксплойта
local execName = "Неизвестно"
if typeof(identifyexecutor) == "function" then
	pcall(function() execName = identifyexecutor() end)
elseif typeof(getexecutorname) == "function" then
	pcall(function() execName = getexecutorname() end)
end
out("Эксплойт: " .. tostring(execName))

-- 2. Карта всех API функций эксплойта
out("\n--- Проверка доступных API функций ---")
local apis = {
	"decompile", "getgc", "getgenv", "getrenv", "getrawmetatable",
	"getconstants", "getupvalues", "getprotos", "getinfo",
	"iscclosure", "islclosure", "newcclosure", "clonefunction",
	"hookfunction", "hookmetamethod", "checkcaller",
	"getscripts", "getscriptbytecode", "getscriptsource",
	"writefile", "readfile", "isfolder", "makefolder"
}

local availableApis = {}
for _, apiName in ipairs(apis) do
	local fn = genv[apiName] or (debug and debug[apiName]) or _G[apiName]
	local exists = (typeof(fn) == "function" or typeof(fn) == "table")
	out(string.format("  %-20s : %s", apiName, exists and "ОК (+)" or "НЕТ (-)"))
	if exists then table.insert(availableApis, apiName) end
end

-- 3. Безопасный хук loadstring
local origLS = genv.loadstring or _G.loadstring or loadstring

if typeof(origLS) ~= "function" then
	out("\n(!) КРИТИЧЕСКАЯ ОШИБКА: loadstring не найден в окружении!")
else
	out("\n--- loadstring перехвачен и готов к отслеживанию ---")
	
	local loadstringCount = 0

	local function inspectorLoadstring(src, chunkname)
		loadstringCount = loadstringCount + 1
		local currentId = loadstringCount
		
		out("\n==================================================")
		out(string.format(">>> ВЫЗОВ loadstring #%d <<<", currentId))
		out("ChunkName: " .. tostring(chunkname or "не указано"))
		out("Тип аргумента: " .. typeof(src))
		out("Длина исходника: " .. (type(src) == "string" and #src or 0) .. " символов")

		if type(src) == "string" then
			local preview = src:sub(1, 150):gsub("%c", " ")
			out("Превью исходника: " .. preview .. (#src > 150 and "..." or ""))
		end

		-- ПРЯМОЙ ВЫЗОВ оригинального loadstring (гарантирует отсутствие nil-ошибок)
		local results = table.pack(origLS(src, chunkname))
		local compiledFn = (results.n >= 1 and typeof(results[1]) == "function") and results[1] or nil
		local errResult = (compiledFn == nil and results.n >= 2) and tostring(results[2]) or nil

		out("Результат компиляции: " .. (compiledFn and "УСПЕХ (функция создана)" or ("ОШИБКА: " .. tostring(errResult))))

		-- Анализ скомпилированного объекта в памяти
		if compiledFn then
			out("\n--- Анализ функции в RAM (loadstring #" .. currentId .. ") ---")
			
			-- Тест decompile
			local decompileFn = genv.decompile or (typeof(decompile) == "function" and decompile or nil)
			if decompileFn then
				local decOk, decRes = pcall(decompileFn, compiledFn)
				if decOk and type(decRes) == "string" and #decRes > 0 then
					out("decompile(fn): УСПЕШНО (получено " .. #decRes .. " символов)")
					out("Превью декомпиляции: " .. decRes:sub(1, 120):gsub("%c", " ") .. "...")
				else
					out("decompile(fn): НЕ СРАБОТАЛ -> " .. tostring(decRes))
				end
			end

			-- Тест debug.getinfo
			local getinfoFn = (debug and typeof(debug.getinfo) == "function") and debug.getinfo or genv.getinfo
			if getinfoFn then
				pcall(function()
					local info = getinfoFn(compiledFn)
					if type(info) == "table" then
						out(string.format("debug.getinfo: source=%s | linedefined=%s | lastline=%s | nparams=%s | what=%s",
							tostring(info.source or info.short_src or "?"),
							tostring(info.linedefined or 0),
							tostring(info.lastlinedefined or 0),
							tostring(info.nparams or 0),
							tostring(info.what or "?")
						))
					end
				end)
			end

			-- Тест getconstants
			local getconstFn = genv.getconstants or _G.getconstants
			if getconstFn then
				local cOk, cRes = pcall(getconstFn, compiledFn)
				if cOk and type(cRes) == "table" then
					out("getconstants: найдено " .. #cRes .. " констант")
					local sample = {}
					for i = 1, math.min(#cRes, 15) do
						table.insert(sample, tostring(cRes[i]):sub(1, 40))
					end
					out("  Первые константы: " .. table.concat(sample, ", "))
				else
					out("getconstants: ошибка -> " .. tostring(cRes))
				end
			end

			-- Тест getprotos
			local getprotosFn = genv.getprotos or _G.getprotos
			if getprotosFn then
				local pOk, pRes = pcall(getprotosFn, compiledFn)
				if pOk and type(pRes) == "table" then
					out("getprotos: найдено " .. #pRes .. " вложенных функций (прототипов)")
				else
					out("getprotos: ошибка -> " .. tostring(pRes))
				end
			end
		end

		-- Сканирование кучи памяти GC на появление связанных объектов
		local getgcFn = genv.getgc or _G.getgc
		if getgcFn then
			pcall(function()
				local gcObjs = getgcFn()
				if type(gcObjs) == "table" then
					out("getgc(): всего объектов в памяти RAM = " .. #gcObjs)
				end
			end)
		end

		out("<<< КОНЕЦ АНАЛИЗА loadstring #" .. currentId .. " >>>\n")

		-- ВОЗВРАЩАЕМ РОВНО ТО, ЧТО ВЕРНУЛ ОРИГИНАЛЬНЫЙ LOADSTRING
		return table.unpack(results, 1, results.n)
	end

	-- Устанавливаем хук
	genv.loadstring = inspectorLoadstring
	if _G then _G.loadstring = inspectorLoadstring end
end

out("\n[Inspector] Готов. Выполняй свой loadstring — лог записывается в консоль и в " .. LOG_FILE)
pcall(function()
	game:GetService("StarterGui"):SetCore("SendNotification", {
		Title = "RAM Inspector",
		Text = "Скрипт активен! Выполняй loadstring — смотри консоль / " .. LOG_FILE,
		Duration = 6
	})
end)
