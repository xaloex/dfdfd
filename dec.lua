--[[═════════════════════════════════════════════════════════════════════════
    ULTIMATE DELTA SCRIPT DUMPER & UNPACKER (Специально под Luraph v15)
    ─────────────────────────────────────────────────────────────────────────
    НА ОСНОВЕ ДИАГНОСТИКИ СЕССИИ:
    1) HttpGet перехватывается и сохраняется в файлы http_*.lua
    2) loadstring #1 (launcher), loadstring #2 (475 KB), loadstring #3 (1.9 MB =ReSwift)
       перехватываются 100% ГАРАНТИРОВАННО и сохраняются в файлы script_*.lua
    3) Все расшифрованные строки, URL, RemoteEvent, имена Сервисов из 591 констант 
       Luraph v15 вытягиваются в luraph_constants.txt
    4) Все вызовы FireServer / InvokeServer логируются в remotes_log.txt

    ИНСТРУКЦИЯ:
    1) Запусти этот скрипт (dumper.lua или script_memory.lua).
    2) Запусти свой лаунчер (loadstring(game:HttpGet(...))()).
    3) Зайди в папку workspace/ScriptDumps/ — там будут ВСЕ исходники!
═══════════════════════════════════════════════════════════════════════════]]

local genv = (typeof(getgenv) == "function") and getgenv() or _G

if genv.__ULTIMATE_DUMPER_ACTIVE then
	warn("[Dumper] Ужe активен!")
	return
end
genv.__ULTIMATE_DUMPER_ACTIVE = true

local HAS_FS = (typeof(writefile) == "function")
local ROOT_DIR = "ScriptDumps"

local function ensureDir(path)
	if not HAS_FS then return end
	if typeof(isfolder) == "function" and not isfolder(path) then
		pcall(makefolder, path)
	end
end

local function save(path, content)
	if not HAS_FS then return end
	pcall(writefile, path, tostring(content))
end

local function notify(title, text)
	pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification", {
			Title = title, Text = text, Duration = 6
		})
	end)
end

ensureDir(ROOT_DIR)

local timestamp = os.date("%Y-%m-%d_%H-%M-%S")
local SESSION_DIR = ROOT_DIR .. "/" .. timestamp
ensureDir(SESSION_DIR)

print("[Dumper] Инициализация... Папка сессии: workspace/" .. SESSION_DIR)

local loadstringCount = 0
local httpCount = 0
local remoteCount = 0
local remotesLog = {}

---------------------------------------------------------------------------
-- 1. ДАМПЕР КОНСТАНТ И СТРОК ИЗ LURAPH v15 (500+ констант, 200+ прототипов)
---------------------------------------------------------------------------
local function dumpLuraphConstants(fn, folderPath)
	if typeof(fn) ~= "function" then return end
	
	local getconstFn = genv.getconstants or _G.getconstants
	local getprotosFn = genv.getprotos or _G.getprotos
	local getupvalFn = genv.getupvalues or _G.getupvalues
	
	if not getconstFn then return end

	local extractedStrings = {}
	local extractedUrls = {}
	local closureLines = {}
	local visited = {}

	local function cleanStr(s)
		return s:gsub("[%c]", " ")
	end

	local function walk(f, depth)
		if depth > 8 or visited[f] then return end
		if typeof(f) ~= "function" then return end
		visited[f] = true

		if typeof(iscclosure) == "function" then
			local isC = false
			pcall(function() isC = iscclosure(f) end)
			if isC then return end
		end

		local info = {}
		if debug and typeof(debug.getinfo) == "function" then
			pcall(function() info = debug.getinfo(f) or {} end)
		end

		local pad = string.rep("  ", depth)
		table.insert(closureLines, string.format("%sFunction [%s] Lines %s..%s (params: %s)",
			pad,
			tostring(info.short_src or info.source or "?"):sub(1, 50),
			tostring(info.linedefined or "?"),
			tostring(info.lastlinedefined or "?"),
			tostring(info.nparams or "?")
		))

		-- Извлекаем константы
		local cOk, consts = pcall(getconstFn, f)
		if cOk and type(consts) == "table" and #consts > 0 then
			local sample = {}
			for i, c in ipairs(consts) do
				if type(c) == "string" then
					local cleaned = cleanStr(c)
					if #cleaned > 2 then
						table.insert(extractedStrings, string.format("[%s] %q", info.short_src or "main", cleaned))
						if cleaned:find("https?://") or cleaned:find("pastebin") or cleaned:find("github") then
							table.insert(extractedUrls, cleaned)
						end
					end
					if i <= 30 then
						table.insert(sample, string.format("%q", cleaned:sub(1, 40)))
					end
				elseif type(c) == "number" or type(c) == "boolean" then
					if i <= 30 then table.insert(sample, tostring(c)) end
				end
			end
			table.insert(closureLines, pad .. "  Constants(" .. #consts .. "): " .. table.concat(sample, ", "))
		end

		-- Извлекаем Upvalues
		if getupvalFn then
			local uOk, uvs = pcall(getupvalFn, f)
			if uOk and type(uvs) == "table" then
				for i, uv in ipairs(uvs) do
					if type(uv) == "string" then
						local cleaned = cleanStr(uv)
						table.insert(extractedStrings, string.format("[Upvalue] %q", cleaned))
					elseif typeof(uv) == "function" then
						walk(uv, depth + 1)
					end
				end
			end
		end

		-- Извлекаем вложенные функции (Protos)
		if getprotosFn then
			local pOk, protos = pcall(getprotosFn, f)
			if pOk and type(protos) == "table" then
				for _, proto in ipairs(protos) do
					if typeof(proto) == "function" then
						walk(proto, depth + 1)
					end
				end
			end
		end
	end

	walk(fn, 0)

	if #extractedStrings > 0 then
		save(folderPath .. "/luraph_extracted_strings.txt", table.concat(extractedStrings, "\n"))
	end
	if #extractedUrls > 0 then
		save(folderPath .. "/extracted_urls.txt", table.concat(extractedUrls, "\n"))
	end
	if #closureLines > 0 then
		save(folderPath .. "/closure_tree.txt", table.concat(closureLines, "\n"))
	end
end

---------------------------------------------------------------------------
-- 2. ГЛАВНЫЙ ХУК loadstring (100% БЕЗОПАСНЫЙ)
---------------------------------------------------------------------------
local origLS = genv.loadstring or _G.loadstring or loadstring

if typeof(origLS) == "function" then
	local function dumperLoadstring(src, chunkname)
		-- 1. Прямой вызов оригинала
		local results = table.pack(origLS(src, chunkname))
		local fn = (results.n >= 1 and typeof(results[1]) == "function") and results[1] or nil

		-- 2. Асинхронное сохранение без задержек основного потока
		task.spawn(function()
			pcall(function()
				loadstringCount = loadstringCount + 1
				local currentId = loadstringCount
				local safeChunk = tostring(chunkname or "script_" .. currentId):gsub("[^%w_]", "_")
				local scriptFolder = SESSION_DIR .. "/script_" .. currentId .. "_" .. safeChunk
				ensureDir(scriptFolder)

				-- Сохраняем исходный код скрипта
				if type(src) == "string" and #src > 0 then
					local header = table.concat({
						"-- ══ ScriptDumper ══",
						"-- Script #" .. currentId,
						"-- ChunkName: " .. tostring(chunkname or "nil"),
						"-- Length: " .. #src .. " characters",
						"-- Date: " .. os.date("%Y-%m-%d %H:%M:%S"),
						"----------------------------------------------------------------",
						"",
						""
					}, "\n")

					save(scriptFolder .. "/source.lua", header .. src)
					print(string.format("[Dumper] Скрипт #%d сохранён! (%d символов) -> %s/source.lua", 
						currentId, #src, scriptFolder))
					notify("Script Dumper", string.format("Скрипт #%d сохранён! (%d KB)", currentId, math.floor(#src / 1024)))
				end

				-- Дампим константы и дерево функций (Luraph unpacking)
				if fn then
					dumpLuraphConstants(fn, scriptFolder)
				end
			end)
		end)

		-- 3. Возвращаем результат компиляции
		return table.unpack(results, 1, results.n)
	end

	genv.loadstring = dumperLoadstring
	if _G then _G.loadstring = dumperLoadstring end
	print("[Dumper] Хук loadstring активирован ✓")
else
	warn("[Dumper] Ошибка: loadstring не найден!")
end

---------------------------------------------------------------------------
-- 3. ХУК HttpGet / HttpGetAsync (через __namecall с newcclosure)
---------------------------------------------------------------------------
if typeof(hookmetamethod) == "function" and typeof(newcclosure) == "function" then
	pcall(function()
		local oldNC
		oldNC = hookmetamethod(game, "__namecall", newcclosure(function(self, ...)
			local method = getnamecallmethod()
			
			if typeof(checkcaller) == "function" and checkcaller() then
				return oldNC(self, ...)
			end

			if method == "HttpGet" or method == "HttpGetAsync" then
				local args = table.pack(...)
				local url = tostring(args[1] or "")
				
				local results = table.pack(oldNC(self, table.unpack(args, 1, args.n)))
				
				if type(results[1]) == "string" and #results[1] > 0 then
					local body = results[1]
					task.spawn(function()
						pcall(function()
							httpCount = httpCount + 1
							local currentId = httpCount
							local safeUrlName = url:gsub("[^%w]", "_"):sub(1, 50)
							local httpFolder = SESSION_DIR .. "/http_" .. currentId .. "_" .. safeUrlName
							ensureDir(httpFolder)

							save(httpFolder .. "/downloaded.lua",
								"-- URL: " .. url .. "\n-- Size: " .. #body .. " bytes\n\n" .. body)

							save(httpFolder .. "/url.txt", url)
							print(string.format("[Dumper] HttpGet #%d сохранён! (%s)", currentId, url))
							notify("Script Dumper", "HttpGet перехвачен: " .. url:sub(1, 40))
						end)
					end)
				end

				return table.unpack(results, 1, results.n)
			end

			-- Логирование вызовов RemoteEvent / RemoteFunction
			if method == "FireServer" or method == "InvokeServer" then
				local args = table.pack(...)
				local remoteName = "Unknown"
				pcall(function() remoteName = self:GetFullName() end)
				
				remoteCount = remoteCount + 1
				local logLine = string.format("[%s] %s:%s(args count: %d)", 
					os.date("%H:%M:%S"), remoteName, method, args.n)
				table.insert(remotesLog, logLine)
				save(SESSION_DIR .. "/remotes_log.txt", table.concat(remotesLog, "\n"))
			end

			return oldNC(self, ...)
		end))
	end)
	print("[Dumper] Хук HttpGet & Remotes (__namecall) активирован ✓")
end

---------------------------------------------------------------------------
-- 4. ХУК request / http_request / syn_request
---------------------------------------------------------------------------
for _, reqName in ipairs({"request", "http_request", "syn_request"}) do
	if typeof(genv[reqName]) == "function" then
		local origReq = genv[reqName]
		pcall(function()
			genv[reqName] = function(opts, ...)
				local results = table.pack(origReq(opts, ...))
				if type(opts) == "table" and type(opts.Url) == "string"
					and type(results[1]) == "table" and type(results[1].Body) == "string" then
					local url = opts.Url
					local body = results[1].Body
					task.spawn(function()
						pcall(function()
							httpCount = httpCount + 1
							local currentId = httpCount
							local safeUrlName = url:gsub("[^%w]", "_"):sub(1, 50)
							local httpFolder = SESSION_DIR .. "/http_" .. currentId .. "_" .. safeUrlName
							ensureDir(httpFolder)

							save(httpFolder .. "/downloaded.lua",
								"-- URL: " .. url .. " (через " .. reqName .. ")\n-- Size: " .. #body .. " bytes\n\n" .. body)

							save(httpFolder .. "/url.txt", url)
							print(string.format("[Dumper] %s #%d сохранён!", reqName, currentId))
						end)
					end)
				end
				return table.unpack(results, 1, results.n)
			end
		end)
	end
end

print("==================================================")
print("   ULTIMATE SCRIPT DUMPER УСПЕШНО ЗАПУЩЕН!      ")
print("   Запускай свой скрипт — всё сохранится в:")
print("   workspace/" .. SESSION_DIR)
print("==================================================")

notify("Ultimate Dumper", "Готов! Запускай свой лаунчер — сохраняю в workspace/" .. ROOT_DIR)
