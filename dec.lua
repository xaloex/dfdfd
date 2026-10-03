--[[═════════════════════════════════════════════════════════════════════════
    SCRIPT RIPPER v3 — запускать ПЕРВЫМ, потом свой loadstring
    ─────────────────────────────────────────────────────────────────────────
    Перехватывает loadstring / HttpGet / require, дампит:
      - raw исходник
      - decompile() результат
      - getgc() — все функции из памяти + их константы
      - все строки из памяти похожие на код
      - все URL из памяти
    
    Файлы → workspace/Ripped/<сессия>/
═══════════════════════════════════════════════════════════════════════════]]

local genv = getgenv and getgenv() or _G
if genv.__RIPPER then return end
genv.__RIPPER = true

---------------------------------------------------------------------------
-- FS
---------------------------------------------------------------------------
local hasFS = typeof(writefile) == "function"
local ROOT = "Ripped"
local SESS do
	local ok, d = pcall(os.date, "%Y-%m-%d_%H-%M-%S")
	SESS = ROOT .. "/" .. (ok and d or tostring(math.floor(tick())))
end
local dumpN, httpN = 0, 0

local function dir(p)
	if not hasFS then return end
	pcall(function() if not isfolder(p) then makefolder(p) end end)
end
local function w(path, txt)
	if not hasFS then print("[Ripper]", path, "\n", tostring(txt):sub(1, 500)) return end
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
-- БЕЗОПАСНЫЙ ВЫЗОВ (каждая функция в отдельном pcall)
---------------------------------------------------------------------------
local function safe(fn, ...)
	if not fn then return nil end
	local ok, res = pcall(fn, ...)
	if ok then return res end
	return nil
end

---------------------------------------------------------------------------
-- ЯВЛЯЕТСЯ ЛИ СТРОКА КОДОМ / URL
---------------------------------------------------------------------------
local function looksLikeCode(s)
	if type(s) ~= "string" or #s < 30 then return false end
	local n = 0
	for _, kw in ipairs({"function", "local ", "end", "return", "then", "GetService", "game:", "require", "loadstring"}) do
		if s:find(kw, 1, true) then n = n + 1 end
		if n >= 2 then return true end
	end
	return false
end

local function looksLikeUrl(s)
	return type(s) == "string" and s:find("https?://") ~= nil
end

---------------------------------------------------------------------------
-- ОБХОД ЗАМЫКАНИЯ: upvalues + константы + protos рекурсивно
---------------------------------------------------------------------------
local function dumpTree(fn, out, visited, depth)
	if depth > 8 then return end
	if not fn or typeof(fn) ~= "function" then return end
	if visited[fn] then return end
	visited[fn] = true

	-- пропускаем C-функции
	if typeof(iscclosure) == "function" then
		local c = safe(iscclosure, fn)
		if c == true then return end
	end

	-- debug.getinfo
	local info = safe(debug.getinfo, fn) or {}
	local pad = string.rep("  ", depth)
	out[#out+1] = string.format("%sfn src=%s L%s-%s params=%s",
		pad,
		tostring(info.short_src or info.source or "?"):sub(1, 60),
		tostring(info.linedefined or "?"),
		tostring(info.lastlinedefined or "?"),
		tostring(info.nparams or "?")
	)

	-- константы
	if typeof(getconstants) == "function" then
		local consts = safe(getconstants, fn)
		if type(consts) == "table" and #consts > 0 then
			local parts = {}
			for i, c in ipairs(consts) do
				if i > 100 then parts[#parts+1] = "..."; break end
				if type(c) == "string" then
					if #c > 80 then
						parts[#parts+1] = '"' .. c:sub(1,80):gsub("[%c\\\"]", ".") .. '..."'
					else
						parts[#parts+1] = '"' .. c:gsub("[%c\\\"]", ".") .. '"'
					end
				elseif c ~= nil then
					parts[#parts+1] = tostring(c)
				end
			end
			out[#out+1] = pad .. "  K[" .. #consts .. "]: " .. table.concat(parts, ", ")
		end
	end

	-- upvalues
	if typeof(getupvalues) == "function" then
		local uvs = safe(getupvalues, fn)
		if type(uvs) == "table" then
			for i, uv in ipairs(uvs) do
				if i > 50 then out[#out+1] = pad .. "  ...more upvals"; break end
				local t = typeof(uv)
				if t == "string" then
					out[#out+1] = pad .. "  uv" .. i .. '="' .. uv:sub(1,80):gsub("[%c\\\"]",".") .. '"'
				elseif t == "function" then
					out[#out+1] = pad .. "  uv" .. i .. "=<fn>"
					dumpTree(uv, out, visited, depth + 1)
				else
					out[#out+1] = pad .. "  uv" .. i .. "=" .. tostring(uv)
				end
			end
		end
	end

	-- protos (вложенные функции)
	if typeof(getprotos) == "function" then
		local ps = safe(getprotos, fn)
		if type(ps) == "table" then
			for i, p in ipairs(ps) do
				if i > 50 then break end
				if typeof(p) == "function" then
					dumpTree(p, out, visited, depth + 1)
				end
			end
		end
	end
end

---------------------------------------------------------------------------
-- СКАНИРОВАНИЕ GC — вытащить ВСЕ из памяти
---------------------------------------------------------------------------
local function scanGC(compiledFn)
	local codeStrings = {}
	local urls = {}
	local closureLines = {}
	local visited = {}

	-- Если есть скомпилированная функция — дампим её дерево
	if compiledFn and typeof(compiledFn) == "function" then
		dumpTree(compiledFn, closureLines, visited, 0)
	end

	-- getgc
	if typeof(getgc) == "function" then
		local objects = safe(getgc)
		if type(objects) == "table" then
			for _, obj in ipairs(objects) do
				local t = typeof(obj)

				if t == "function" then
					dumpTree(obj, closureLines, visited, 0)

				elseif t == "string" then
					if looksLikeUrl(obj) then
						urls[obj] = true
					end
					if looksLikeCode(obj) then
						codeStrings[#codeStrings+1] = obj
					end

				elseif t == "table" then
					-- поверхностный проход по таблицам из GC
					pcall(function()
						local count = 0
						for k, v in pairs(obj) do
							count = count + 1
							if count > 200 then break end
							if type(v) == "string" then
								if looksLikeUrl(v) then urls[v] = true end
								if looksLikeCode(v) then codeStrings[#codeStrings+1] = v end
							elseif typeof(v) == "function" then
								dumpTree(v, closureLines, visited, 0)
							end
						end
					end)
				end
			end
		end
	end

	-- debug.getregistry
	if debug and typeof(debug.getregistry) == "function" then
		local reg = safe(debug.getregistry)
		if type(reg) == "table" then
			pcall(function()
				for _, v in pairs(reg) do
					if typeof(v) == "function" then
						dumpTree(v, closureLines, visited, 0)
					elseif type(v) == "string" and looksLikeCode(v) then
						codeStrings[#codeStrings+1] = v
					end
				end
			end)
		end
	end

	-- getgenv
	pcall(function()
		for _, v in pairs(genv) do
			if typeof(v) == "function" then
				dumpTree(v, closureLines, visited, 0)
			end
		end
	end)

	-- getrenv (если есть — окружение скрипта)
	if typeof(getrenv) == "function" then
		pcall(function()
			for _, v in pairs(getrenv()) do
				if typeof(v) == "function" then
					dumpTree(v, closureLines, visited, 0)
				end
			end
		end)
	end

	return closureLines, codeStrings, urls
end

---------------------------------------------------------------------------
-- ПОПЫТКА ДЕКОМПИЛЯЦИИ — безопасно, несколько методов
---------------------------------------------------------------------------
local function tryDecompile(fn, rawSrc)
	local results = {}

	-- decompile(fn)
	if typeof(decompile) == "function" and fn and typeof(fn) == "function" then
		local ok, dec = pcall(decompile, fn)
		if ok and type(dec) == "string" and #dec > 5 then
			results[#results+1] = {name="decompile_fn", code=dec}
		end
	end

	-- Если rawSrc это читаемый текст (не байткод) — это УЖЕ исходник
	if type(rawSrc) == "string" and #rawSrc > 5 then
		-- Проверяем: байткод начинается с определённых байтов
		local b1 = rawSrc:byte(1)
		if b1 and b1 > 31 then
			-- Печатный символ = скорее всего текст
			results[#results+1] = {name="raw_source", code=rawSrc}
		else
			-- Похоже на байткод — всё равно сохраняем
			results[#results+1] = {name="raw_bytecode", code=rawSrc}
		end
	end

	return results
end

---------------------------------------------------------------------------
-- ВОССТАНОВЛЕНИЕ ИЗ КОНСТАНТ (когда decompile не дал результат)
---------------------------------------------------------------------------
local function rebuildFromConstants(fn)
	if not fn or typeof(fn) ~= "function" then return nil end
	if typeof(getconstants) ~= "function" then return nil end

	local allStrings = {}
	local visited = {}

	local function collect(f, d)
		if d > 6 or visited[f] then return end
		if typeof(f) ~= "function" then return end
		visited[f] = true
		if typeof(iscclosure) == "function" and safe(iscclosure, f) == true then return end

		local cs = safe(getconstants, f)
		if type(cs) == "table" then
			for _, c in ipairs(cs) do
				if type(c) == "string" and #c > 3 then
					allStrings[#allStrings+1] = c
				end
			end
		end

		if typeof(getupvalues) == "function" then
			local uvs = safe(getupvalues, f)
			if type(uvs) == "table" then
				for _, uv in ipairs(uvs) do
					if type(uv) == "string" and #uv > 3 then
						allStrings[#allStrings+1] = uv
					elseif typeof(uv) == "function" then
						collect(uv, d + 1)
					end
				end
			end
		end

		if typeof(getprotos) == "function" then
			local ps = safe(getprotos, f)
			if type(ps) == "table" then
				for _, p in ipairs(ps) do
					if typeof(p) == "function" then collect(p, d + 1) end
				end
			end
		end
	end

	collect(fn, 0)
	if #allStrings == 0 then return nil end

	local out = {"-- [Ripper] REBUILT FROM CONSTANTS (" .. #allStrings .. " strings)", ""}
	for i, s in ipairs(allStrings) do
		out[#out+1] = "-- [" .. i .. "] len=" .. #s
		out[#out+1] = s
		out[#out+1] = ""
	end
	return table.concat(out, "\n")
end

---------------------------------------------------------------------------
-- ДАМП СКРИПТОВ ПОЯВИВШИХСЯ В ИГРЕ
---------------------------------------------------------------------------
local function dumpGameScripts(folder)
	if typeof(getscripts) ~= "function" then return end
	local scripts = safe(getscripts)
	if type(scripts) ~= "table" then return end

	local idx = 0
	for _, s in ipairs(scripts) do
		pcall(function()
			if not (s:IsA("LocalScript") or s:IsA("ModuleScript")) then return end
			idx = idx + 1
			if idx > 30 then return end

			local safeName = s.Name:gsub("[^%w_]", "_"):sub(1, 30)

			-- decompile на Instance — безопасно
			if typeof(decompile) == "function" then
				local ok, dec = pcall(decompile, s)
				if ok and type(dec) == "string" and #dec > 5 then
					w(folder .. "/game_" .. idx .. "_" .. safeName .. ".lua",
						"-- " .. s:GetFullName() .. "\n\n" .. dec)
				end
			end

			-- getscriptbytecode
			if typeof(getscriptbytecode) == "function" then
				local ok, bc = pcall(getscriptbytecode, s)
				if ok and type(bc) == "string" and #bc > 0 then
					w(folder .. "/bytecode_" .. idx .. "_" .. safeName .. ".bin", bc)
				end
			end
		end)
	end
end

---------------------------------------------------------------------------
-- ГЛАВНЫЙ ОБРАБОТЧИК ПЕРЕХВАТА
---------------------------------------------------------------------------
local function onCapture(rawSrc, chunkName, compiledFn)
	dumpN = dumpN + 1
	local folder = SESS .. "/catch_" .. dumpN
	dir(folder)

	print(("[Ripper] ═══ CATCH #%d ═══ chunk=%s size=%d"):format(
		dumpN,
		tostring(chunkName or "?"):sub(1, 40),
		type(rawSrc) == "string" and #rawSrc or 0
	))

	-- ── 1. ДЕКОМПИЛЯЦИЯ ─────────────────────────────────────────────
	local decResults = tryDecompile(compiledFn, rawSrc)
	for i, r in ipairs(decResults) do
		w(folder .. "/" .. r.name .. ".lua",
			"-- method: " .. r.name .. "\n-- chunk: " .. tostring(chunkName or "?")
			.. "\n-- size: " .. #r.code .. "\n\n" .. r.code)
		print("[Ripper] Saved: " .. r.name .. " (" .. #r.code .. " chars)")
	end

	-- ── 2. ПОЛНЫЙ СКАН ПАМЯТИ ───────────────────────────────────────
	task.defer(function()
		pcall(function()
			-- Ждём чтобы скрипт успел выполнить первые инструкции
			task.wait(0.5)

			local closureLines, codeStrings, urls = scanGC(compiledFn)

			-- Дерево функций
			if #closureLines > 0 then
				w(folder .. "/functions.txt", table.concat(closureLines, "\n"))
				print("[Ripper] Functions: " .. #closureLines .. " lines")
			end

			-- Строки-код из памяти
			if #codeStrings > 0 then
				local out = {"-- [Ripper] CODE STRINGS FROM MEMORY (" .. #codeStrings .. ")", ""}
				for i, s in ipairs(codeStrings) do
					if i > 300 then out[#out+1] = "...(truncated)"; break end
					out[#out+1] = "-- [" .. i .. "] len=" .. #s
					out[#out+1] = s
					out[#out+1] = ""
				end
				w(folder .. "/memory_strings.txt", table.concat(out, "\n"))
				print("[Ripper] Code strings: " .. #codeStrings)
			end

			-- URL
			local urlList = {}
			for u in pairs(urls) do urlList[#urlList+1] = u end
			if #urlList > 0 then
				w(folder .. "/urls.txt", table.concat(urlList, "\n"))
				print("[Ripper] URLs: " .. #urlList)
			end

			-- Восстановление из констант
			local rebuilt = rebuildFromConstants(compiledFn)
			if rebuilt then
				w(folder .. "/rebuilt_constants.lua", rebuilt)
				print("[Ripper] Rebuilt from constants saved")
			end

			-- Скрипты из игры
			dumpGameScripts(folder)

			local m = ("Catch #%d готов → %s"):format(dumpN, folder)
			print("[Ripper] " .. m)
			msg("Ripper", m)
		end)
	end)
end

---------------------------------------------------------------------------
-- ХУК loadstring
---------------------------------------------------------------------------
local origLS = genv.loadstring or (rawget and rawget(_G, "loadstring")) or loadstring

if typeof(origLS) == "function" then
	local hook = function(src, name)
		-- Компилируем через оригинал
		local fn, err
		pcall(function()
			fn, err = origLS(src, name)
		end)

		-- Дамп асинхронно
		task.spawn(function()
			pcall(onCapture, src, name, typeof(fn) == "function" and fn or nil)
		end)

		return fn, err
	end

	-- Подменяем
	pcall(function() genv.loadstring = hook end)
	pcall(function() _G.loadstring = hook end)

	-- hookfunction как резерв
	if genv.loadstring ~= hook and typeof(hookfunction) == "function" then
		pcall(function()
			local old = hookfunction(origLS, hook)
			if typeof(old) == "function" then
				origLS = old
			end
		end)
	end

	print("[Ripper] loadstring hook ✓")
else
	warn("[Ripper] loadstring не найден!")
end

---------------------------------------------------------------------------
-- ХУК HttpGet через __namecall
---------------------------------------------------------------------------
if typeof(hookmetamethod) == "function" then
	pcall(function()
		local oldNC
		oldNC = hookmetamethod(game, "__namecall", function(self, ...)
			local method = getnamecallmethod()

			if method == "HttpGet" or method == "HttpGetAsync" then
				local url = tostring(select(1, ...) or "")

				-- Вызываем оригинал
				local results = {oldNC(self, ...)}

				-- Сохраняем ответ
				if type(results[1]) == "string" and #results[1] > 0 then
					task.spawn(function()
						pcall(function()
							httpN = httpN + 1
							local safeName = url:gsub("[^%w]", "_"):sub(1, 40)
							w(SESS .. "/http_" .. httpN .. "_" .. safeName .. ".lua",
								"-- URL: " .. url .. "\n-- size: " .. #results[1] .. "\n\n" .. results[1])
							print("[Ripper] HttpGet saved: " .. url:sub(1, 60))
						end)
					end)
				end

				return unpack(results)
			end

			return oldNC(self, ...)
		end)
	end)
	print("[Ripper] __namecall hook ✓")
end

---------------------------------------------------------------------------
-- ХУК request
---------------------------------------------------------------------------
for _, rn in ipairs({"request", "http_request", "syn_request"}) do
	if typeof(genv[rn]) == "function" then
		local orig = genv[rn]
		pcall(function()
			genv[rn] = function(opts, ...)
				local res = {orig(opts, ...)}
				if type(opts) == "table" and type(opts.Url) == "string"
					and type(res[1]) == "table" and type(res[1].Body) == "string" then
					task.spawn(function()
						pcall(function()
							httpN = httpN + 1
							local safeName = opts.Url:gsub("[^%w]","_"):sub(1,40)
							w(SESS .. "/http_" .. httpN .. "_" .. safeName .. ".lua",
								"-- URL: " .. opts.Url .. "\n\n" .. res[1].Body)
						end)
					end)
				end
				return unpack(res)
			end
		end)
		print("[Ripper] " .. rn .. " hook ✓")
	end
end

---------------------------------------------------------------------------
-- ДОПОЛНИТЕЛЬНО: ловим require (модули)
---------------------------------------------------------------------------
if typeof(hookfunction) == "function" then
	pcall(function()
		local origReq = require
		if typeof(origReq) == "function" then
			local oldReq = hookfunction(origReq, function(module, ...)
				local result = oldReq(module, ...)

				task.spawn(function()
					pcall(function()
						if typeof(module) == "Instance" then
							dumpN = dumpN + 1
							local folder = SESS .. "/require_" .. dumpN
							dir(folder)
							w(folder .. "/info.txt", "require(" .. module:GetFullName() .. ")")

							if typeof(decompile) == "function" then
								local ok, dec = pcall(decompile, module)
								if ok and type(dec) == "string" then
									w(folder .. "/decompiled.lua", dec)
								end
							end
						end
					end)
				end)

				return result
			end)
		end
	end)
	print("[Ripper] require hook ✓")
end

---------------------------------------------------------------------------
print("[Ripper] ══ ACTIVE ══ Запускай свой скрипт → workspace/" .. SESS)
msg("ScriptRipper", "Жду loadstring → " .. ROOT)
