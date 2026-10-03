--[[═════════════════════════════════════════════════════════════════════════
    DELTA SCRIPT RIPPER — совместим с Delta Executor
    ─────────────────────────────────────────────────────────────────────────
    ПРАВИЛА DELTA:
      • hookmetamethod ОБЯЗАТЕЛЬНО через newcclosure() — иначе краш
      • hookfunction(Instance.new) — НЕ ИСПОЛЬЗОВАТЬ — крашит Delta
      • checkcaller() — использовать ВНУТРИ хуков чтобы не ловить свои вызовы
      • __newindex хук — НЕ ИСПОЛЬЗОВАТЬ — бесконечная рекурсия на Delta

    ПОРЯДОК:
      1) Запусти ЭТОТ скрипт
      2) Запусти обфусцированный скрипт (Luraph и т.п.)
      3) Подожди пока он отработает
      4) Напиши /dump в чат — трассировка сохранится
      5) Или она автосохранится через 15 секунд и далее каждые 10 сек

    ВЫХОД: workspace/DeltaRip/<сессия>/
      trace.lua       — все API вызовы как читаемый Lua-код
      raw_log.txt     — полный лог
      remotes.txt     — FireServer / InvokeServer
      strings.txt     — все строки из памяти
      http_N.lua      — тела HttpGet
      loadstring_N.lua — перехваченные исходники
═══════════════════════════════════════════════════════════════════════════]]

local genv = getgenv and getgenv() or _G

if genv.__DELTA_RIP then
	warn("[DeltaRip] Уже активен")
	return
end
genv.__DELTA_RIP = true

---------------------------------------------------------------------------
-- FS
---------------------------------------------------------------------------
local hasFS = typeof(writefile) == "function"
local ROOT = "DeltaRip"
local SESS do
	local ok, d = pcall(os.date, "%Y-%m-%d_%H-%M-%S")
	SESS = ROOT .. "/" .. (ok and d or tostring(math.floor(tick())))
end
local lsIdx, httpIdx = 0, 0

local function dir(p)
	if not hasFS then return end
	pcall(function() if not isfolder(p) then makefolder(p) end end)
end
local function w(path, txt)
	if not hasFS then return end
	pcall(writefile, path, tostring(txt))
end
local function msg(title, text)
	pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification",
			{Title = title, Text = text, Duration = 5})
	end)
end

dir(ROOT)
dir(SESS)

---------------------------------------------------------------------------
-- ЛОГИРОВАНИЕ
---------------------------------------------------------------------------
local rawLog = {}
local traceCode = {}
local remoteCalls = {}
local capturedStrings = {}
local startTime = tick()
local totalCalls = 0

local function ts()
	return string.format("[%.2f]", tick() - startTime)
end

local function repr(v, d)
	d = d or 0
	if d > 2 then return "..." end
	local t = typeof(v)
	if t == "string" then
		capturedStrings[v] = true
		if #v > 100 then return '"' .. v:sub(1,100):gsub('[%c\\"]','.') .. '..."' end
		return '"' .. v:gsub('[%c\\"]','.') .. '"'
	elseif t == "number" or t == "boolean" or t == "nil" then
		return tostring(v)
	elseif t == "Instance" then
		local ok, n = pcall(function() return v:GetFullName() end)
		return ok and n or "<Instance>"
	elseif t == "table" then
		local parts = {}
		local cnt = 0
		pcall(function()
			for k, val in pairs(v) do
				cnt = cnt + 1
				if cnt > 6 then parts[#parts+1] = "..."; break end
				if type(k) == "number" then
					parts[#parts+1] = repr(val, d+1)
				else
					parts[#parts+1] = tostring(k) .. "=" .. repr(val, d+1)
				end
			end
		end)
		return "{" .. table.concat(parts, ", ") .. "}"
	elseif t == "Vector3" or t == "Vector2" or t == "CFrame"
		or t == "Color3" or t == "UDim2" or t == "UDim"
		or t == "BrickColor" or t == "EnumItem" then
		local ok, s = pcall(tostring, v)
		return ok and s or "<" .. t .. ">"
	elseif t == "function" then
		return "<function>"
	end
	local ok, s = pcall(tostring, v)
	return ok and s or "<" .. t .. ">"
end

local function reprArgs(...)
	local a = table.pack(...)
	local p = {}
	for i = 1, a.n do p[i] = repr(a[i]) end
	return table.concat(p, ", ")
end

local function log(cat, code, raw)
	totalCalls = totalCalls + 1
	if #rawLog < 20000 then
		rawLog[#rawLog+1] = ts() .. " " .. (raw or code)
	end
	if #traceCode < 15000 then
		traceCode[#traceCode+1] = code
	end
	if cat == "remote" then
		remoteCalls[#remoteCalls+1] = ts() .. " " .. (raw or code)
	end
end

---------------------------------------------------------------------------
-- ХУК __namecall — ГЛАВНЫЙ ПЕРЕХВАТЧИК
-- ОБЯЗАТЕЛЬНО newcclosure() на Delta!!!
---------------------------------------------------------------------------
if typeof(hookmetamethod) == "function" and typeof(newcclosure) == "function" then
	pcall(function()
		local oldNC
		oldNC = hookmetamethod(game, "__namecall", newcclosure(function(self, ...)
			local method = getnamecallmethod()

			-- Пропускаем свои вызовы (Delta поддерживает checkcaller)
			if checkcaller() then
				return oldNC(self, ...)
			end

			local selfName = ""
			pcall(function() selfName = self:GetFullName() end)
			local argsStr = reprArgs(...)

			-- ── FireServer / InvokeServer ──
			if method == "FireServer" or method == "InvokeServer" then
				log("remote",
					selfName .. ":" .. method .. "(" .. argsStr .. ")",
					"[REMOTE] " .. selfName .. ":" .. method .. "(" .. argsStr .. ")")

			-- ── HttpGet ──
			elseif method == "HttpGet" or method == "HttpGetAsync" then
				local url = tostring(select(1, ...) or "")
				log("api", 'game:' .. method .. '("' .. url:sub(1,80) .. '")')

				-- Сохраняем ответ
				local results = table.pack(oldNC(self, ...))
				if type(results[1]) == "string" and #results[1] > 0 then
					task.spawn(function()
						pcall(function()
							httpIdx = httpIdx + 1
							w(SESS .. "/http_" .. httpIdx .. ".lua",
								"-- URL: " .. url .. "\n-- size: " .. #results[1] .. "\n\n" .. results[1])
						end)
					end)
				end
				return table.unpack(results, 1, results.n)

			-- ── Connect ──
			elseif method == "Connect" or method == "connect" or method == "Once" then
				log("api", selfName .. ":" .. method .. "(<callback>)")

			-- ── GetService ──
			elseif method == "GetService" then
				log("api", 'game:GetService(' .. argsStr .. ')')

			-- ── Instance manipulation ──
			elseif method == "Clone" or method == "Destroy" or method == "Remove" then
				log("api", selfName .. ':' .. method .. '()')

			-- ── Teleport / Kick ──
			elseif method == "Kick" or method == "Teleport" then
				log("api",
					selfName .. ':' .. method .. '(' .. argsStr .. ')',
					"[" .. method:upper() .. "] " .. argsStr)

			-- ── WaitForChild / FindFirstChild ──
			elseif method == "FindFirstChild" or method == "WaitForChild"
				or method == "FindFirstChildOfClass" or method == "FindFirstChildWhichIsA" then
				log("api", selfName .. ':' .. method .. '(' .. argsStr .. ')')

			-- ── MoveTo / TweenService ──
			elseif method == "MoveTo" or method == "PivotTo" or method == "Create" then
				log("api", selfName .. ':' .. method .. '(' .. argsStr .. ')')

			-- ── Play / Stop (Sound, Tween, Animation) ──
			elseif method == "Play" or method == "Stop" or method == "Pause" then
				log("api", selfName .. ':' .. method .. '()')

			-- ── SetAttribute / GetAttribute ──
			elseif method == "SetAttribute" or method == "GetAttribute" then
				log("api", selfName .. ':' .. method .. '(' .. argsStr .. ')')

			-- ── Прочее (фильтруем шум) ──
			elseif method ~= "IsA" and method ~= "IsDescendantOf"
				and method ~= "IsAncestorOf" and method ~= "GetPropertyChangedSignal"
				and method ~= "GetChildren" and method ~= "GetDescendants"
				and method ~= "GetFullName" and method ~= "FindFirstAncestor" then
				log("api", selfName .. ':' .. method .. '(' .. argsStr .. ')')
			end

			return oldNC(self, ...)
		end))
	end)
	print("[DeltaRip] __namecall hook ✓ (через newcclosure)")
elseif typeof(hookmetamethod) == "function" then
	-- Без newcclosure — рискованно, но пробуем
	warn("[DeltaRip] newcclosure не найден! __namecall хук может крашнуть")
	pcall(function()
		local oldNC
		oldNC = hookmetamethod(game, "__namecall", function(self, ...)
			local method = getnamecallmethod()
			if typeof(checkcaller) == "function" and checkcaller() then
				return oldNC(self, ...)
			end
			local selfName = ""
			pcall(function() selfName = self:GetFullName() end)
			local argsStr = reprArgs(...)

			if method == "FireServer" or method == "InvokeServer" then
				log("remote", selfName .. ":" .. method .. "(" .. argsStr .. ")")
			elseif method == "HttpGet" or method == "HttpGetAsync" then
				log("api", 'game:' .. method .. '(' .. argsStr .. ')')
				local res = table.pack(oldNC(self, ...))
				if type(res[1]) == "string" and #res[1] > 0 then
					task.spawn(function() pcall(function()
						httpIdx = httpIdx + 1
						w(SESS .. "/http_" .. httpIdx .. ".lua", "-- " .. tostring(select(1,...) or "") .. "\n\n" .. res[1])
					end) end)
				end
				return table.unpack(res, 1, res.n)
			elseif method ~= "IsA" and method ~= "GetChildren" and method ~= "GetDescendants"
				and method ~= "GetFullName" and method ~= "IsDescendantOf" then
				log("api", selfName .. ":" .. method .. "(" .. argsStr .. ")")
			end

			return oldNC(self, ...)
		end)
	end)
	print("[DeltaRip] __namecall hook ✓ (без newcclosure — может быть нестабильно)")
else
	warn("[DeltaRip] hookmetamethod недоступен!")
end

---------------------------------------------------------------------------
-- ХУК loadstring — ловим исходники и decompile
-- Прямая подмена (НЕ hookfunction) — безопаснее на Delta
---------------------------------------------------------------------------
local origLS = genv.loadstring or loadstring

if typeof(origLS) == "function" then
	local hook = function(src, name)
		local fn, err
		pcall(function() fn, err = origLS(src, name) end)

		task.spawn(function()
			pcall(function()
				lsIdx = lsIdx + 1
				local folder = SESS .. "/ls_" .. lsIdx
				dir(folder)

				-- RAW source
				if type(src) == "string" and #src > 0 then
					w(folder .. "/raw.lua",
						"-- chunk: " .. tostring(name or "?")
						.. "\n-- size: " .. #src .. "\n\n" .. src)
				end

				-- decompile
				if typeof(decompile) == "function" and typeof(fn) == "function" then
					local ok, dec = pcall(decompile, fn)
					if ok and type(dec) == "string" and #dec > 5 then
						w(folder .. "/decompiled.lua", dec)
					end
				end

				-- getgc + constants + upvalues + protos
				if typeof(fn) == "function" then
					local lines = {"=== FUNCTION TREE ===", ""}
					local vis = {}

					local function walk(f, depth)
						if depth > 6 or vis[f] then return end
						if typeof(f) ~= "function" then return end
						vis[f] = true

						if typeof(iscclosure) == "function" then
							local ok, c = pcall(iscclosure, f)
							if ok and c then return end
						end

						local info = {}
						if debug and typeof(debug.getinfo) == "function" then
							pcall(function() info = debug.getinfo(f) or {} end)
						end

						local pad = ("  "):rep(depth)
						lines[#lines+1] = pad .. string.format("fn [%s] L%s-%s p=%s",
							tostring(info.short_src or "?"):sub(1,40),
							tostring(info.linedefined or "?"),
							tostring(info.lastlinedefined or "?"),
							tostring(info.nparams or "?"))

						if typeof(getconstants) == "function" then
							local ok, cs = pcall(getconstants, f)
							if ok and type(cs) == "table" and #cs > 0 then
								local p = {}
								for i, c in ipairs(cs) do
									if i > 80 then p[#p+1] = "..."; break end
									if type(c) == "string" then
										capturedStrings[c] = true
										p[#p+1] = (#c > 60) and ('"'..c:sub(1,60):gsub('[%c\\"]','.')..'"') or ('"'..c:gsub('[%c\\"]','.')..'"')
									elseif c ~= nil then
										p[#p+1] = tostring(c)
									end
								end
								lines[#lines+1] = pad .. "  K["..#cs.."]: " .. table.concat(p, ", ")
							end
						end

						if typeof(getupvalues) == "function" then
							local ok, uvs = pcall(getupvalues, f)
							if ok and type(uvs) == "table" then
								for i, uv in ipairs(uvs) do
									if i > 40 then break end
									if type(uv) == "string" then
										capturedStrings[uv] = true
										lines[#lines+1] = pad .. "  uv"..i..'="'..uv:sub(1,60):gsub('[%c\\"]','.')..'"'
									elseif typeof(uv) == "function" then
										walk(uv, depth+1)
									end
								end
							end
						end

						if typeof(getprotos) == "function" then
							local ok, ps = pcall(getprotos, f)
							if ok and type(ps) == "table" then
								for i, p in ipairs(ps) do
									if i > 40 then break end
									if typeof(p) == "function" then walk(p, depth+1) end
								end
							end
						end
					end

					walk(fn, 0)
					w(folder .. "/functions.txt", table.concat(lines, "\n"))
				end

				print("[DeltaRip] loadstring #" .. lsIdx .. " → " .. folder)
				log("api", 'loadstring(<' .. (type(src)=="string" and #src or 0) .. ' chars>)')
			end)
		end)

		return fn, err
	end

	pcall(function() genv.loadstring = hook end)
	pcall(function() _G.loadstring = hook end)

	-- hookfunction как резерв
	if genv.loadstring ~= hook and typeof(hookfunction) == "function" then
		pcall(function()
			local old = hookfunction(origLS, hook)
			if typeof(old) == "function" then origLS = old end
		end)
	end

	print("[DeltaRip] loadstring hook ✓")
end

---------------------------------------------------------------------------
-- ХУК request / http_request / syn_request
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
						httpIdx = httpIdx + 1
						w(SESS .. "/req_" .. httpIdx .. ".lua",
							"-- " .. opts.Url .. "\n\n" .. res[1].Body)
						log("api", rn .. '({Url="' .. opts.Url:sub(1,80) .. '"})')
					end
				end)
				return unpack(res)
			end
		end)
	end
end

---------------------------------------------------------------------------
-- GC SCAN — вытащить строки из памяти (через 10 сек после запуска)
---------------------------------------------------------------------------
task.delay(10, function()
	pcall(function()
		if typeof(getgc) ~= "function" then return end
		local objs = getgc()
		if type(objs) ~= "table" then return end

		local code = {}
		for _, obj in ipairs(objs) do
			if type(obj) == "string" and #obj > 25 and #obj < 100000 then
				local n = 0
				for _, kw in ipairs({"function","local ","end","return","then","game","require","loadstring"}) do
					if obj:find(kw, 1, true) then n = n + 1 end
				end
				if n >= 2 then code[#code+1] = obj end
			end
		end

		if #code > 0 then
			table.sort(code, function(a,b) return #a > #b end)
			local out = {"-- GC CODE STRINGS: " .. #code, ""}
			for i, s in ipairs(code) do
				if i > 150 then break end
				out[#out+1] = "-- [" .. i .. "] len=" .. #s
				out[#out+1] = s
				out[#out+1] = ""
			end
			w(SESS .. "/gc_code.txt", table.concat(out, "\n"))
			print("[DeltaRip] GC: " .. #code .. " code fragments")
		end

		-- Все строки с URL
		local urls = {}
		for _, obj in ipairs(objs) do
			if type(obj) == "string" and obj:find("https?://") then
				urls[#urls+1] = obj
			end
		end
		if #urls > 0 then
			w(SESS .. "/gc_urls.txt", table.concat(urls, "\n"))
		end
	end)
end)

---------------------------------------------------------------------------
-- СОХРАНЕНИЕ
---------------------------------------------------------------------------
local function saveAll()
	if totalCalls == 0 and lsIdx == 0 then return end

	w(SESS .. "/trace.lua", table.concat({
		"-- ═══ DELTA RIP TRACE ═══",
		"-- Calls: " .. totalCalls,
		"-- Time: " .. string.format("%.1f", tick()-startTime) .. "s",
		"-- ═══════════════════════",
		"",
		table.concat(traceCode, "\n")
	}, "\n"))

	w(SESS .. "/raw_log.txt", table.concat(rawLog, "\n"))

	if #remoteCalls > 0 then
		w(SESS .. "/remotes.txt", table.concat(remoteCalls, "\n"))
	end

	local strList = {}
	for s in pairs(capturedStrings) do
		if #s > 2 and #s < 10000 then strList[#strList+1] = s end
	end
	if #strList > 0 then
		table.sort(strList, function(a,b) return #a > #b end)
		w(SESS .. "/strings.txt", table.concat(strList, "\n---\n"))
	end

	print(("[DeltaRip] Saved: %d calls, %d remotes, %d strings → %s"):format(
		totalCalls, #remoteCalls, #strList, SESS))
end

-- Автосохранение
task.spawn(function()
	task.wait(15) -- первое сохранение через 15 сек
	while genv.__DELTA_RIP do
		pcall(saveAll)
		task.wait(10)
	end
end)

-- /dump команда
pcall(function()
	local lp = game:GetService("Players").LocalPlayer
	if lp then
		lp.Chatted:Connect(function(m)
			if m:lower() == "/dump" then
				pcall(saveAll)
				msg("DeltaRip", totalCalls .. " вызовов сохранено!")
			end
		end)
	end
end)

-- При выходе
pcall(function() game:BindToClose(function() pcall(saveAll) end) end)

---------------------------------------------------------------------------
print("[DeltaRip] ══ ACTIVE ══ Запускай скрипт → workspace/" .. SESS)
print("[DeltaRip] Через 15сек автосохранение, или /dump в чат")
msg("DeltaRip", "ACTIVE! Запускай скрипт → " .. ROOT)
