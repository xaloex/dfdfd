--[[═════════════════════════════════════════════════════════════════════════
    VM-DUMP  —  выкачивает VM Luraph v15 и превращает её в читаемый исходник2

    ЗАПУСК:
      1) запустить ЭТОТ файл (первым!)
      2) потом запустить свой loadstring с обфусцированным скриптом

    КУДА СКЛАДЫВАЕТ:
      workspace/VM-Dump/<дата_время>/
        00_REPORT.txt          — что перехвачено, какие хуки/шимы встали
        chunk_001_*.lua        — исходник как есть (побайтно)
        chunk_001_*.pretty.lua — РАЗБИТЫЙ ПО СТРОКАМ, с отступами (читаемый)
        chunk_001_*.b64.txt    — если это байткод (ECR), плюс .bin
        vm_blobs/              — зашифрованные блобы, которые прячет Luraph
        strings.txt            — все строковые константы
        missing_globals.txt    — вызывается, но отсутствует в окружении
        outline.txt            — все функции + их константы
        globals_after/         — новые глобалы после запуска payload
        http/                  — всё, что скачали по сети

    ШИМЫ (обязательны): Luraph v15 зовёт bit32.band/bxor/countrz, setfenv,
    unpack и load. Если их нет в эксплоите — VM падает на первой строке и
    не отдаёт ничего. Здесь они ставятся автоматически.
══════════════════════════════════════════════════════════════════════════]]

---------------------------------------------------------------------------
-- 0. СОСТОЯНИЕ
---------------------------------------------------------------------------
local okGenv, genv = pcall(function()
	if type(getgenv) == "function" then return getgenv() end
	return _G
end)
if not okGenv or type(genv) ~= "table" then genv = _G end

local STATE_KEY = "__VM_DUMP_STATE"

local function stateRef()
	local ok, v = pcall(rawget, _G, STATE_KEY)
	if type(v) == "table" then return v end
	ok, v = pcall(rawget, genv, STATE_KEY)
	if type(v) == "table" then return v end
	return nil
end

local prevState = stateRef()
if type(prevState) == "table" and prevState.active then
	print("[VMDump] Already running. VMDUMP_RETRY() re-installs hooks.")
	return
end

local userCfg = rawget(genv, "VM_DUMP_CFG")
if type(userCfg) ~= "table" then userCfg = {} end

local S = {
	active = true,
	dir = nil,
	cfg = {
		format = userCfg.format ~= false,       -- разбивать исходник по строкам
		breakTables = userCfg.breakTables ~= false,
		analyze = userCfg.analyze ~= false,
		hookRemotes = userCfg.hookRemotes ~= false,
		walkProtos = userCfg.walkProtos ~= false,
		maxFormats = userCfg.maxFormats or 6,
		verbose = userCfg.verbose ~= false,
	},
	chunks = {},
	httpCount = 0,
	seen = {},
	strings = {},
	blobs = {},
	logBuf = {},
	outline = {},
	remoteLog = {},
	remHooked = {},
	remBase = {},
	prev = {},
	shims = {},
	counter = 0,
	walkCount = 0,
}
rawset(genv, STATE_KEY, S)
if _G and _G ~= genv then pcall(rawset, _G, STATE_KEY, S) end

---------------------------------------------------------------------------
-- 1. ФАЙЛЫ
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
	local cur = ""
	for piece in relDir:gmatch("[^/]+") do
		cur = (cur == "") and piece or (cur .. "/" .. piece)
		makeDir(S.dir .. "/" .. cur)
	end
end

function S.log(msg)
	local line = string.format("[%s] %s", os.date("%H:%M:%S"), tostring(msg))
	S.logBuf[#S.logBuf + 1] = line
	if #S.logBuf > 600 then table.remove(S.logBuf, 1) end
	if S.cfg.verbose then print("[VMDump] " .. tostring(msg)) end
	if S.hasWrite and S.dir then
		pcall(writefile, S.dir .. "/00_REPORT.txt", S.buildReport())
	end
end

function S.save(rel, content)
	if not S.hasWrite then return false end
	local d = rel:match("^(.*)[/][^/]*$")
	if d and d ~= "" then ensureRelDir(d) end
	local ok, err = pcall(writefile, S.dir .. "/" .. rel, content)
	if not ok then print("[VMDump] WRITE FAIL " .. rel .. ": " .. tostring(err)) end
	return (ok and true) or false
end

function S.saveRaw(rel, data)
	if not S.hasWrite then return false end
	local d = rel:match("^(.*)[/][^/]*$")
	if d and d ~= "" then ensureRelDir(d) end
	pcall(writefile, S.dir .. "/" .. rel, data)
	return true
end

local ROOT_DIR = "VM-Dump"
makeDir(ROOT_DIR)
S.dir = ROOT_DIR .. "/" .. os.date("%Y-%m-%d_%H-%M-%S")
makeDir(S.dir)
S.dirName = S.dir

print("[VMDump] folder: workspace/" .. S.dir)
if not S.hasWrite then print("[VMDump] WARNING: no writefile - nowhere to save!") end

---------------------------------------------------------------------------
-- 2. УТИЛИТЫ
---------------------------------------------------------------------------
local function hashStr(s)
	local h, n = 5381, #s
	local step = (n > 8192) and math.floor(n / 8192) or 1
	for i = 1, n, step do h = (h * 33 + s:byte(i)) % 4294967296 end
	return string.format("%08x_%d", h, n)
end

local function notify(title, text)
	pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification", {
			Title = title, Text = text, Duration = 5
		})
	end)
end

local function isBinary(s)
	if s:find("\0", 1, true) then return true end
	if s:sub(1, 1) == "\27" then return true end
	return false
end

local function b64(data)
	local CH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	local n, i, out, buf, cnt = #data, 1, {}, {}, 0
	local function enc(q)
		if q < 26 then return string.char(65 + q) end
		if q < 52 then return string.char(71 + q - 26) end
		if q < 62 then return string.char(48 + q - 52) end
		if q == 62 then return "+" end
		return "/"
	end
	while i <= n do
		local a, b, c = data:byte(i, i + 2)
		local v = a * 65536 + (b or 0) * 256 + (c or 0)
		buf[#buf + 1] = enc(math.floor(v / 262144))
		buf[#buf + 1] = enc(math.floor(v / 4096) % 64)
		buf[#buf + 1] = enc(math.floor(v / 64) % 64)
		buf[#buf + 1] = enc(v % 64)
		cnt = cnt + 1
		if cnt >= 1024 then out[#out + 1] = table.concat(buf); buf = {}; cnt = 0 end
		i = i + 3
	end
	if cnt > 0 then out[#out + 1] = table.concat(buf) end
	local r = table.concat(out)
	local rem = n % 3
	if rem == 1 then r = r:sub(1, #r - 2) .. "=="
	elseif rem == 2 then r = r:sub(1, #r - 1) .. "=" end
	return r
end

local function hexDump(s, maxBytes)
	maxBytes = maxBytes or 128
	local p = {}
	for i = 1, math.min(#s, maxBytes) do p[#p + 1] = string.format("%02X", s:byte(i)) end
	return table.concat(p, " ")
end

---------------------------------------------------------------------------
-- 3. РАЗБОР ИСХОДНИКА: имена / строки / блобы
---------------------------------------------------------------------------
local LUA_KEYWORDS = {
	["and"]=true, ["break"]=true, ["do"]=true, ["else"]=true, ["elseif"]=true,
	["end"]=true, ["false"]=true, ["for"]=true, ["function"]=true, ["if"]=true,
	["in"]=true, ["local"]=true, ["nil"]=true, ["not"]=true, ["or"]=true,
	["repeat"]=true, ["return"]=true, ["then"]=true, ["true"]=true,
	["until"]=true, ["while"]=true, ["continue"]=true, ["export"]=true,
	["goto"]=true, ["type"]=true,
}

local KNOWN_GLOBALS = {
	["_G"]=true, ["_VERSION"]=true, ["assert"]=true, ["error"]=true,
	["pairs"]=true, ["ipairs"]=true, ["next"]=true, ["rawequal"]=true,
	["rawlen"]=true, ["collectgarbage"]=true, ["setmetatable"]=true,
	["getmetatable"]=true, ["rawget"]=true, ["rawset"]=true,
	["xpcall"]=true, ["tonumber"]=true, ["tostring"]=true, ["typeof"]=true,
	["select"]=true, ["unpack"]=true, ["print"]=true, ["warn"]=true,
	["pcall"]=true, ["loadstring"]=true, ["load"]=true, ["require"]=true,
	["newproxy"]=true, ["coroutine"]=true, ["debug"]=true, ["math"]=true,
	["os"]=true, ["io"]=true, ["string"]=true, ["table"]=true,
	["bit"]=true, ["bit32"]=true, ["utf8"]=true, ["buffer"]=true, ["task"]=true,
	["tick"]=true, ["time"]=true, ["delay"]=true, ["spawn"]=true, ["wait"]=true,
	["game"]=true, ["workspace"]=true, ["script"]=true,
	["Instance"]=true, ["Enum"]=true, ["CFrame"]=true, ["Vector2"]=true,
	["Vector3"]=true, ["Color3"]=true, ["UDim"]=true, ["UDim2"]=true,
	["Random"]=true, ["Ray"]=true, ["Region3"]=true, ["BrickColor"]=true,
	["TweenService"]=true, ["RunService"]=true, ["UserInputService"]=true,
	["Players"]=true, ["ReplicatedStorage"]=true, ["ServerStorage"]=true,
	["ServerScriptService"]=true, ["StarterGui"]=true, ["StarterPlayer"]=true,
	["Lighting"]=true, ["SoundService"]=true, ["Teams"]=true,
	["HttpService"]=true, ["MarketplaceService"]=true, ["TeleportService"]=true,
	["UserSettings"]=true, ["GuiService"]=true, ["ContextActionService"]=true,
	["getgenv"]=true, ["getrenv"]=true, ["getcallingscript"]=true,
	["hookfunction"]=true, ["hookmetamethod"]=true, ["newcclosure"]=true,
	["checkcaller"]=true, ["checknamecall"]=true, ["getnamecallmethod"]=true,
	["setfenv"]=true, ["getfenv"]=true, ["getconstants"]=true, ["getprotos"]=true,
	["getupvalues"]=true, ["getconstant"]=true, ["getupvalue"]=true,
	["writefile"]=true, ["readfile"]=true, ["appendfile"]=true,
	["makefolder"]=true, ["isfolder"]=true, ["listfiles"]=true,
	["request"]=true, ["http_request"]=true, ["syn"]=true, ["shared"]=true,
	["identifyexecutor"]=true, ["getexecutorname"]=true, ["getgc"]=true,
	["Synapse"]=true, ["Fluxus"]=true, ["Krnl"]=true, ["Solara"]=true,
}

local SCAN_LIMIT = 7000000

-- один проход: собирает имена (с позициями), строки и длинные блобы
local function scanLua(src)
	local names, strings, blobs = {}, {}, {}
	local nameMap, total = {}, #src
	local n = math.min(total, SCAN_LIMIT)
	local i, line = 1, 1

	local function bump(from, to)
		local seg = src:sub(from, to)
		if seg then local _, c = seg:gsub("\n", "") line = line + c end
	end

	local function skipString(start)
		local quote = src:sub(start, start)
		local j = start + 1
		while j <= n do
			local ch = src:sub(j, j)
			if ch == "\\" then
				if src:sub(j + 1, j + 1):match("%d") then
					local k = j + 1
					while k <= n and k <= j + 3 and src:sub(k, k):match("%d") do k = k + 1 end
					j = k
				elseif src:sub(j + 1, j + 1) == "x" then
					local k = j + 2
					while k <= n and k <= j + 3 and src:sub(k, k):match("%x") do k = k + 1 end
					j = k
				else
					j = j + 2
				end
			elseif ch == quote then j = j + 1 break
			elseif ch == "\n" then break
			else j = j + 1 end
		end
		return j
	end

	while i <= n do
		local prev = i
		local c = src:sub(i, i)
		if c == "-" and src:sub(i, i + 1) == "--" then
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
			local body = src:sub(i, (e and e + #close - 1) or n)
			if #body > 300 then blobs[#blobs + 1] = body end
			i = (e and e + #close) or (n + 1)
		elseif c == '"' or c == "'" then
			local j = skipString(i)
			strings[#strings + 1] = src:sub(i, j - 1)
			i = j
		elseif c:match("[%a_]") then
			local j = i
			while j <= n and src:sub(j, j):match("[%w_]") do j = j + 1 end
			local name = src:sub(i, j - 1)
			local p = i - 1
			while p >= 1 and src:sub(p, p):match("%s") do p = p - 1 end
			local prevCh = (p >= 1) and src:sub(p, p) or ""
			local isMember = (prevCh == "." or prevCh == ":")
			local isAssign = src:sub(j):match("^%s*=[^=]") ~= nil
			if not isMember and not isAssign and not LUA_KEYWORDS[name]
				and not KNOWN_GLOBALS[name] then
				local r = nameMap[name]
				if not r then
					r = {
						name = name, count = 0, called = false, line = line,
						ctx = src:sub(math.max(1, i - 45), math.min(total, j + 55)):gsub("[\r\n]+", " "),
					}
					nameMap[name] = r
					names[#names + 1] = r
				end
				r.count = r.count + 1
				if not r.called and src:sub(j):match("^%s*%(") then
					r.called, r.line = true, line
					r.ctx = src:sub(math.max(1, i - 45), math.min(total, j + 55)):gsub("[\r\n]+", " ")
				end
			end
			i = j
		else
			i = i + 1
		end
		bump(prev, i - 1)
	end
	return names, strings, blobs, total
end

local function declaredNames(src)
	local out = {}
	local head = src:sub(1, math.min(#src, SCAN_LIMIT))
	for m in head:gmatch("local%s+([%a_][%w_]*)") do out[m] = true end
	for m in head:gmatch("local%s+[%a_][%w_]*%s*,%s*([%a_][%w_]*)") do out[m] = true end
	for m in head:gmatch("function%s+([%a_][%w_]*)") do out[m] = true end
	for m in head:gmatch("function%s+[%a_][%w_]*%s*%(([^%)]*)%)") do
		for p in m:gmatch("[%a_][%w_]*") do out[p] = true end
	end
	for k, v in head:gmatch("for%s+([%a_][%w_]*)%s*,%s*([%a_][%w_]*)%s+in") do
		if k then out[k] = true end
		if v then out[v] = true end
	end
	return out
end

local function globalExists(name)
	local ok, v = pcall(function() return _G[name] end)
	if ok and v ~= nil then return true end
	ok, v = pcall(function() return genv[name] end)
	if ok and v ~= nil then return true end
	local okc, cur = pcall(function() return getfenv(0) end)
	if okc and type(cur) == "table" then
		local ok2, v2 = pcall(function() return cur[name] end)
		if ok2 and v2 ~= nil then return true end
	end
	return false
end

---------------------------------------------------------------------------
-- 4. ФОРМАТИРОВАНИЕ (то самое "читаемый исходник")
---------------------------------------------------------------------------
local MULTI_OPS = {
	"//=", "<<=", ">>=", "...",
	"==", "~=", "<=", ">=", "//", "<<", ">>", "->", "::", "..=",
	"+=", "-=", "*=", "/=", "%=", "^=", "..",
}
local NO_SPACE_BEFORE = {
	[")"] = true, ["]"] = true, [","] = true, [";"] = true, ["."] = true,
	[":"] = true, ["::"] = true, ["?"] = true, ["("] = true, ["["] = true,
}
local NO_SPACE_AFTER = { ["("] = true, ["["] = true, ["."] = true, ["::"] = true }
local WORD_THEN_SPACE = {
	["if"] = true, ["while"] = true, ["for"] = true, ["and"] = true,
	["or"] = true, ["not"] = true, ["return"] = true, ["in"] = true,
	["do"] = true, ["then"] = true, ["else"] = true, ["elseif"] = true,
	["until"] = true, ["repeat"] = true, ["local"] = true, ["function"] = true,
}
local BLOCK_OPEN = { ["function"] = true, ["then"] = true, ["do"] = true, ["repeat"] = true }
local STMT_START_KW = {
	["local"] = true, ["return"] = true, ["if"] = true, ["while"] = true,
	["for"] = true, ["function"] = true, ["repeat"] = true, ["break"] = true,
}

local function matchOp(s, i)
	for k = 1, #MULTI_OPS do
		local op = MULTI_OPS[k]
		if s:sub(i, i + #op - 1) == op then return op end
	end
	return s:sub(i, i)
end

-- Раскладывает исходник по строкам с отступами. Ничего не удаляет, кроме
-- ";" (он в Lua необязателен), поэтому результат остаётся рабочим кодом.
-- Раскладывает исходник по строкам с отступами. Ничего не удаляет, кроме
-- ";" (в Lua он необязателен), поэтому результат остаётся рабочим кодом.
-- Раскладывает исходник по строкам с отступами. Ничего не удаляет, кроме
-- ";" (в Lua он необязателен), поэтому результат остаётся рабочим кодом.
local function formatLua(src)
	local total = #src
	local i = 1
	local indent, depth, brace = 0, 0, 0
	local atStart = true
	local prev = ""      -- тип предыдущего токена: "w" слово, "0" число, ")" и т.п.
	local prevWord = ""  -- точное имя предыдущего слова (нужно для скобок)
	local out, buf, cnt = {}, {}, 0
	local pendingIndent = false
	local emitted = false

	local function emit(s)
		buf[#buf + 1] = s
		cnt = cnt + 1
		if cnt >= 1024 then
			out[#out + 1] = table.concat(buf)
			buf, cnt = {}, 0
		end
	end

	-- отступ ставится лениво: перед следующим токеном, а не сразу после \n,
	-- иначе появляются строки из одних табов
	local function put(s)
		if pendingIndent then
			pendingIndent = false
			if indent > 0 then emit(string.rep("\t", indent)) end
		end
		emitted = true
		emit(s)
	end

	local function nl()
		-- не начинаем вывод с пустой строки и не делаем две подряд
		if not emitted or pendingIndent then return end
		emit("\n")
		pendingIndent = true
		atStart, prev, prevWord = true, "", ""
	end

	while i <= total do
		local c = src:sub(i, i)

		if c == "-" and src:sub(i, i + 1) == "--" then
			local lb = src:match("^%-%-%[(=*)%[", i)
			local stop
			if lb then
				local close = "]" .. lb .. "]"
				stop = src:find(close, i, true)
				stop = (stop and stop + #close - 1) or total
			else
				local e = src:find("\n", i, true)
				stop = (e and e - 1) or total
			end
			if prev ~= "" then nl() end
			put(src:sub(i, stop))
			prev = "\n"
			i = stop + 1

		elseif c == "[" and src:match("^%[(=*)%[", i) then
			local lb = src:match("^%[(=*)%[", i)
			local close = "]" .. lb .. "]"
			local e = src:find(close, i, true)
			local stop = (e and e + #close - 1) or total
			if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put(src:sub(i, stop))
			prev = "]"
			i = stop + 1

		elseif c == '"' or c == "'" then
			local quote = c
			local j = i + 1
			while j <= total do
				local ch = src:sub(j, j)
				if ch == "\\" then
					if src:sub(j + 1, j + 1):match("%d") then
						local k = j + 1
						while k <= total and k <= j + 3 and src:sub(k, k):match("%d") do k = k + 1 end
						j = k
					elseif src:sub(j + 1, j + 1) == "x" then
						local k = j + 2
						while k <= total and k <= j + 3 and src:sub(k, k):match("%x") do k = k + 1 end
						j = k
					else
						j = j + 2
					end
				elseif ch == quote then
					j = j + 1
					break
				elseif ch == "\n" then
					break
				else
					j = j + 1
				end
			end
			if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put(src:sub(i, j - 1))
			prev = "\""
			i = j

		elseif c:match("[%a_]") then
			local j = i
			while j <= total and src:sub(j, j):match("[%w_]") do j = j + 1 end
			local word = src:sub(i, j - 1)
			if LUA_KEYWORDS[word] then
				if word == "function" or word == "then" or word == "do" or word == "repeat" then
					-- заголовок (if ... then / while ... do) остаётся в одну строку,
					-- переносим только function/repeat в начале предложения
					if depth == 0 and (word == "function" or word == "repeat") and atStart then nl() end
					if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
					put(word)
					indent = indent + 1
					atStart, prev, prevWord = true, word, word
				elseif word == "end" or word == "until" then
					indent = math.max(0, indent - 1)
					nl()
					put(word)
					atStart, prev, prevWord = false, word, word
				elseif word == "else" or word == "elseif" then
					indent = math.max(0, indent - 1)
					nl()
					put(word)
					indent = indent + 1
					-- после "elseif" условие идёт в ту же строку, после "else" — с новой
					atStart, prev, prevWord = (word == "else"), word, word
				else
					-- новое предложение: начало строки либо сразу после ")"
					if STMT_START_KW[word] and (atStart or prev == ")") then nl() end
					if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
					put(word)
					atStart, prev, prevWord = false, word, word
				end
			else
				if atStart then nl() end
				if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
				put(word)
				atStart, prev, prevWord = false, "w", word
			end
			i = j

		elseif c:match("%d") or (c == "." and src:sub(i + 1, i + 1):match("%d")) then
			local j = i
			while j <= total do
				local ch = src:sub(j, j)
				if ch:match("[%w%._]") then
					j = j + 1
				elseif (ch == "-" or ch == "+") and src:sub(j - 1, j - 1):match("[eEpP]") then
					j = j + 1
				else
					break
				end
			end
			if atStart then nl() end
			if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put(src:sub(i, j - 1))
			atStart, prev, prevWord = false, "0", ""
			i = j

		elseif c == "{" then
			if prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put("{")
			prev = "{"
			brace = brace + 1
			if S.cfg.breakTables then
				indent = indent + 1
				nl()
			else
				atStart = false
			end
			i = i + 1

		elseif c == "}" then
			if S.cfg.breakTables then
				indent = math.max(0, indent - 1)
				nl()
			end
			put("}")
			brace = math.max(0, brace - 1)
			atStart, prev, prevWord = false, "}", ""
			i = i + 1

		elseif c == "," then
			-- запятая внутри таблицы-конструктора = новое поле на новой строке
			put(",")
			if S.cfg.breakTables and brace > 0 and depth == 0 then nl() end
			atStart, prev, prevWord = false, ",", ""
			i = i + 1

		elseif c == "(" then
			local tight = ((prev == "w" and not WORD_THEN_SPACE[prevWord])
				or prev == "0" or prev == ")" or prev == "]"
				or prev == "\"" or prev == "}")
			if not tight and prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put("(")
			depth = depth + 1
			atStart, prev, prevWord = false, "(", ""
			i = i + 1

		elseif c == ")" then
			put(")")
			depth = math.max(0, depth - 1)
			atStart, prev, prevWord = false, ")", ""
			i = i + 1

		elseif c == "[" then
			local tight = ((prev == "w" and not WORD_THEN_SPACE[prevWord])
				or prev == "0" or prev == ")" or prev == "]"
				or prev == "\"" or prev == "}")
			if not tight and prev ~= "" and not NO_SPACE_AFTER[prev] then put(" ") end
			put("[")
			depth = depth + 1
			atStart, prev, prevWord = false, "[", ""
			i = i + 1

		elseif c == "]" then
			put("]")
			depth = math.max(0, depth - 1)
			atStart, prev, prevWord = false, "]", ""
			i = i + 1

		elseif c == ";" then
			nl()
			i = i + 1

		elseif c:match("%s") then
			local e = i
			while e <= total and src:sub(e, e):match("%s") do e = e + 1 end
			i = e

		else
			local op = matchOp(src, i)
			if op == ":" or op == "?" then
				-- перед ":" и "?" пробел не ставим никогда (obj:Method, T?)
				put(op)
				prev, prevWord = "", ""
			else
				if atStart then nl() end
				if prev ~= "" and not NO_SPACE_AFTER[prev] and not NO_SPACE_BEFORE[op] then
					put(" ")
				end
				put(op)
				prev, prevWord = op, ""
			end
			atStart = false
			i = i + #op
		end
	end

	if cnt > 0 then out[#out + 1] = table.concat(buf) end
	return table.concat(out)
end

---------------------------------------------------------------------------
-- 5. ШИМЫ (без них VM не запустится)
---------------------------------------------------------------------------
local function toU32(x)
	x = tonumber(x) or 0
	return math.floor(x) % 4294967296
end

local function mkBand(a, b)
	local r, v = 0, 1
	a, b = toU32(a), toU32(b)
	for _ = 1, 32 do
		if a % 2 == 1 and b % 2 == 1 then r = r + v end
		a = (a - a % 2) / 2
		b = (b - b % 2) / 2
		v = v * 2
	end
	return r
end

local function mkBor(a, b)
	local r, v = 0, 1
	a, b = toU32(a), toU32(b)
	for _ = 1, 32 do
		if a % 2 == 1 or b % 2 == 1 then r = r + v end
		a = (a - a % 2) / 2
		b = (b - b % 2) / 2
		v = v * 2
	end
	return r
end

local function mkBxor(a, b)
	local r, v = 0, 1
	a, b = toU32(a), toU32(b)
	for _ = 1, 32 do
		if (a % 2) ~= (b % 2) then r = r + v end
		a = (a - a % 2) / 2
		b = (b - b % 2) / 2
		v = v * 2
	end
	return r
end

local function mkLshift(x, n)
	n = n % 32
	local u = toU32(x)
	if n == 0 then return u end
	return (u % (2 ^ (32 - n))) * (2 ^ n)
end

local function mkRshift(x, n)
	n = n % 32
	if n == 0 then return toU32(x) end
	return math.floor(toU32(x) / (2 ^ n))
end

local function mkRrotate(x, n)
	n = n % 32
	local u = toU32(x)
	if n == 0 then return u end
	return (math.floor(u / (2 ^ n)) + (u % (2 ^ n)) * (2 ^ (32 - n))) % 4294967296
end

local function mkLrotate(x, n)
	n = n % 32
	local u = toU32(x)
	if n == 0 then return u end
	return ((u % (2 ^ (32 - n))) * (2 ^ n) + math.floor(u / (2 ^ (32 - n)))) % 4294967296
end

local function mkCountlz(x)
	local u = toU32(x)
	if u == 0 then return 32 end
	local n = 0
	while u < 2147483648 do
		u = u * 2
		n = n + 1
	end
	return n
end

local function mkCountrz(x)
	local u = toU32(x)
	if u == 0 then return 32 end
	local n = 0
	while u % 2 == 0 do
		u = u / 2
		n = n + 1
	end
	return n
end

local function makeBit32()
	local bitlib = rawget(_G, "bit")
	if type(bitlib) ~= "table" then bitlib = rawget(genv, "bit") end
	local B, origin = {}, "pure-lua"
	local function fast(nm) return type(bitlib) == "table" and type(bitlib[nm]) == "function" end
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
		B.band, B.bor, B.bxor = mkBand, mkBor, mkBxor
		B.bnot = function(a) return 4294967295 - toU32(a) end
		B.lshift, B.rshift = mkLshift, mkRshift
		B.rrotate, B.lrotate = mkRrotate, mkLrotate
	end
	B.countlz, B.countrz = mkCountlz, mkCountrz
	B.len = function() return 32 end
	B.arshift = function(a, n)
		n = n % 32
		local u = toU32(a)
		local sg = (u >= 2147483648) and (u - 4294967296) or u
		local r = (n == 0) and sg or math.floor(sg / (2 ^ n))
		if r >= 2147483648 then return r - 4294967296 end
		return r
	end
	B.extract = function(v, f, w)
		f, w = f % 32, w % 32
		if w == 0 then return 0 end
		return math.floor(toU32(v) / (2 ^ f)) % (2 ^ w)
	end
	B.replace = function(v, n2, f, w)
		f, w = f % 32, w % 32
		if w == 0 then return toU32(v) end
		local u = toU32(v)
		local cl = u - (math.floor(u / (2 ^ f)) % (2 ^ w)) * (2 ^ f)
		return (cl + (toU32(n2) % (2 ^ w)) * (2 ^ f)) % 4294967296
	end
	return B, origin
end

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

local function applyShim(name, value)
	local ok = false
	for _, t in ipairs(envTargets()) do
		if pcall(rawset, t, name, value) then ok = true end
	end
	S.shims[name] = ok and "installed" or "FAILED (read-only env)"
	return ok
end

local function tagHook(fn, base)
	if type(fn) ~= "function" then return fn end
	pcall(function() fn.__vmdumpHook = true end)
	pcall(function() fn.__vmdumpBase = base or fn end)
	return fn
end

local function isOurHook(fn)
	if type(fn) ~= "function" then return false end
	local ok, v = pcall(function() return fn.__vmdumpHook end)
	return (ok and v == true) or false
end

local function baseOf(fn)
	if type(fn) ~= "function" then return fn end
	if isOurHook(fn) then
		local ok, b = pcall(function() return fn.__vmdumpBase end)
		if ok and type(b) == "function" then return b end
	end
	return fn
end

local function makeNative(fn)
	if type(newcclosure) ~= "function" then return fn end
	local ok, res = pcall(newcclosure, fn)
	if ok and type(res) == "function" then return tagHook(res, fn) end
	return fn
end

local function installShims()
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
		S.shims.bit32 = "patched existing (" .. origin .. "): " .. table.concat(added, ",")
	else
		applyShim("bit32", B)
		S.shims.bit32 = "created (" .. origin .. ")"
	end
	S.log("shim bit32: " .. tostring(S.shims.bit32))

	if type(rawget(_G, "setfenv")) ~= "function" and type(rawget(genv, "setfenv")) ~= "function" then
		applyShim("setfenv", function(f, env)
			if type(env) == "table" then
				for k, v in pairs(env) do
					if rawget(_G, k) == nil then pcall(rawset, _G, k, v) end
				end
			end
			local ok, e = pcall(getfenv, 0)
			if ok and type(e) == "table" then return e end
			return env
		end)
		S.shims.setfenv = "created (env merged into _G)"
	end

	if type(rawget(_G, "unpack")) ~= "function" and type(table.unpack) == "function" then
		applyShim("unpack", table.unpack)
		S.shims.unpack = "created (= table.unpack)"
	end

	if type(rawget(_G, "load")) ~= "function" and type(rawget(genv, "load")) ~= "function" then
		applyShim("load", function(chunk, name, ...)
			local ls = rawget(genv, "loadstring") or rawget(_G, "loadstring")
			if type(ls) == "function" then return ls(chunk, name, ...) end
			return nil, "loadstring unavailable"
		end)
		S.shims.load = "created (= hooked loadstring)"
		S.log("shim load: created, calls through it are captured too")
	end

	if type(rawget(_G, "getfenv")) ~= "function" and type(rawget(genv, "getfenv")) ~= "function" then
		applyShim("getfenv", function() return _G end)
		S.shims.getfenv = "created"
	end

	if type(rawget(_G, "newproxy")) ~= "function" and type(rawget(genv, "newproxy")) ~= "function" then
		applyShim("newproxy", function(addMt)
			local t = {}
			if addMt then setmetatable(t, {}) end
			return t
		end)
		S.shims.newproxy = "created (table instead of proxy)"
	end

	if type(rawget(_G, "require")) ~= "function" and type(rawget(genv, "require")) ~= "function" then
		applyShim("require", function()
			local proxy
			proxy = setmetatable({}, {
				__index = function(_, k)
					local fn = function() return proxy end
					rawset(proxy, k, fn)
					return fn
				end,
				__call = function() return proxy end,
			})
			return proxy
		end)
		S.shims.require = "created (permissive proxy)"
	end

	if type(rawget(_G, "identifyexecutor")) ~= "function" then
		applyShim("identifyexecutor", function() return "VMDump" end)
	end
	if type(rawget(_G, "getexecutorname")) ~= "function" then
		applyShim("getexecutorname", function() return "VMDump" end)
	end
	if type(rawget(_G, "hookfunction")) ~= "function" then
		applyShim("hookfunction", function(target, repl)
			if type(target) == "table" and type(repl) == "function" then
				pcall(rawset, target, "__vmdumpHook", true)
			end
			return function() end
		end)
		S.shims.hookfunction = "created (no-op)"
	end
	if type(rawget(_G, "getgc")) ~= "function" then
		applyShim("getgc", function() return {} end)
	end
end

---------------------------------------------------------------------------
-- 6. ПЕРЕХВАТ КОМПИЛЯЦИИ
---------------------------------------------------------------------------
local hookCount = 0

local function buildChunkHook(orig, tag)
	local wrapper = function(...)
		local packed = table.pack(...)
		local ok, a, b, c = pcall(orig, table.unpack(packed, 1, packed.n))
		local St = stateRef()
		if type(St) == "table" and type(St.onChunk) == "function" then
			pcall(St.onChunk, packed[1], packed[2], tag, ok, a)
		end
		if not ok then error(a, 0) end
		return a, b, c
	end
	return tagHook(makeNative(wrapper), orig)
end

local function install(name, tag)
	local orig = rawget(genv, name) or rawget(_G, name)
	if type(orig) ~= "function" then return false end
	if isOurHook(orig) then return true end
	local wrapped = buildChunkHook(orig, tag)
	local a = pcall(function() rawset(genv, name, wrapped) end)
	local b = pcall(function() rawset(_G, name, wrapped) end)
	if a or b then
		hookCount = hookCount + 1
		S.log("hook " .. name .. " installed")
		return true
	end
	return false
end

---------------------------------------------------------------------------
-- 7. HTTP
---------------------------------------------------------------------------
function S.saveHttp(url, body, method)
	if type(body) ~= "string" or #body == 0 then return end
	S.httpCount = S.httpCount + 1
	local n = S.httpCount
	local h = hashStr(body)
	if S.seen["h" .. h] then return end
	S.seen["h" .. h] = true
	local safe = tostring(url or "?"):gsub("[^%w]", "_"):sub(1, 60)
	S.save("http/" .. n .. "_" .. safe .. ".lua",
		"-- URL: " .. tostring(url) .. "\n-- via: " .. tostring(method) .. "\n\n" .. body)
	S.log("HTTP #" .. n .. " " .. tostring(method) .. " " .. tostring(url))
end

local function patchHttp()
	if type(hookmetamethod) ~= "function" then return end
	local ok, svc = pcall(function() return game:GetService("HttpService") end)
	if ok and type(svc) == "instance" then
		local namecall = function(self, ...)
			local method = getnamecallmethod()
			local base = S.prev.http
			if type(base) ~= "function" then return end
			if method == "RequestAsync" or method == "Request"
				or method == "GetAsync" or method == "Get" then
				local first = select(1, ...)
				local url = "?"
				if type(first) == "table" then url = first.Url or first.URL or "?"
				elseif type(first) == "string" then url = first end
				local res = table.pack(base(self, ...))
				pcall(S.saveHttp, url, type(res[1]) == "string" and res[1] or nil, method)
				return table.unpack(res, 1, res.n)
			end
			return base(self, ...)
		end
		tagHook(namecall)
		local ok2, prev = pcall(hookmetamethod, svc, "__namecall", makeNative(namecall))
		if ok2 and type(prev) == "function" then S.prev.http = baseOf(prev) end
	end

	local namecall2 = function(self, ...)
		local method = getnamecallmethod()
		local base = S.prev.game
		if type(base) ~= "function" then return end
		if method == "HttpGet" or method == "HttpGetAsync"
			or method == "HttpPost" or method == "HttpPostAsync" then
			local url = select(1, ...)
			local res = table.pack(base(self, ...))
			pcall(S.saveHttp, tostring(url), type(res[1]) == "string" and res[1] or nil, method)
			return table.unpack(res, 1, res.n)
		end
		return base(self, ...)
	end
	tagHook(namecall2)
	local ok3, prev2 = pcall(hookmetamethod, game, "__namecall", makeNative(namecall2))
	if ok3 and type(prev2) == "function" then S.prev.game = baseOf(prev2) end
end

local function installRequest(name, holder)
	local orig = rawget(holder, name)
	if type(orig) ~= "function" then return end
	if isOurHook(orig) then return end
	local wrapper = function(...)
		local res = table.pack(orig(...))
		local opts = select(1, ...)
		local url, body = nil, nil
		if type(opts) == "table" then url = opts.Url or opts.URL end
		for k = 1, res.n do
			local v = res[k]
			if type(v) == "string" and #v > 0 and (not body or #v > #body) then body = v end
		end
		pcall(S.saveHttp, tostring(url), body, name)
		return table.unpack(res, 1, res.n)
	end
	tagHook(wrapper, orig)
	local ok = pcall(function() rawset(holder, name, makeNative(wrapper)) end)
	if ok then
		S.log("hook " .. name .. " installed")
		hookCount = hookCount + 1
	end
end

---------------------------------------------------------------------------
-- 8. ENV-ПАТЧИ
---------------------------------------------------------------------------
local function patchEnv(env)
	if type(env) ~= "table" then return end
	for _, name in ipairs({"loadstring", "load"}) do
		local cur = rawget(env, name)
		if type(cur) == "function" and not isOurHook(cur) then
			pcall(rawset, env, name, buildChunkHook(cur, name .. "_env"))
		end
	end
end

local function installEnvHooks()
	local origGet = rawget(genv, "getfenv")
	if type(origGet) == "function" and not isOurHook(origGet) then
		local w = function(f)
			local env = origGet(f)
			if type(env) == "table" then pcall(patchEnv, env) end
			return env
		end
		tagHook(w, origGet)
		if pcall(function() rawset(genv, "getfenv", makeNative(w)) end) then
			S.log("hook getfenv installed")
		end
	end
	local origSet = rawget(genv, "setfenv")
	if type(origSet) == "function" and not isOurHook(origSet) then
		local w = function(f, env)
			if type(env) == "table" then pcall(patchEnv, env) end
			return origSet(f, env)
		end
		tagHook(w, origSet)
		if pcall(function() rawset(genv, "setfenv", makeNative(w)) end) then
			S.log("hook setfenv installed")
		end
	end
end

---------------------------------------------------------------------------
-- 9. ОБХОД ЗАМЫКАНИЙ
---------------------------------------------------------------------------
local function walkFn(fn, depth)
	if type(fn) ~= "function" then return end
	if depth > 8 then return end
	S.walkCount = S.walkCount + 1
	if S.walkCount > 40000 then return end
	local pad = string.rep("  ", depth)
	local gp = rawget(genv, "getprotos") or rawget(_G, "getprotos")
	if type(gp) ~= "function" then return end
	local ok, protos = pcall(gp, fn)
	if ok and type(protos) == "table" then
		local gc = rawget(genv, "getconstants") or rawget(_G, "getconstants")
		for _, proto in pairs(protos) do
			if type(proto) == "function" then
				local consts = {}
				if type(gc) == "function" then
					local cok, cs = pcall(gc, proto)
					if cok and type(cs) == "table" then
						local shown = 0
						for _, c in pairs(cs) do
							if type(c) == "string" and #c > 2 and shown < 6 then
								consts[#consts + 1] = string.format("%q", c:sub(1, 40))
								shown = shown + 1
							end
						end
					end
				end
				S.outline[#S.outline + 1] = string.format("%sfn  %s",
					pad, table.concat(consts, " "))
				walkFn(proto, depth + 1)
			end
		end
	end
end

---------------------------------------------------------------------------
-- 10. РАЗБОР ПЕРЕХВАЧЕННОГО CHUNK-А
---------------------------------------------------------------------------
function S.onChunk(src, chunkname, tag, ok, compiled)
	if type(src) == "function" then
		local dok, dumped = pcall(string.dump, src)
		if dok and type(dumped) == "string" then
			S.counter = S.counter + 1
			S.saveRaw("chunk_" .. S.counter .. "_fn.dump.bin", dumped)
			S.save("chunk_" .. S.counter .. "_fn.dump.b64.txt", b64(dumped))
		end
		return
	end
	if type(src) ~= "string" or #src < 2 then return end
	if src:find("__VMDUMP_PROBE__", 1, true) then return end
	if src:find(STATE_KEY, 1, true) then return end

	S.counter = S.counter + 1
	local n = S.counter
	local h = hashStr(src)
	if S.seen[h] then
		S.log("dup #" .. n .. " (" .. tag .. ") skipped, len=" .. #src)
		return
	end
	S.seen[h] = true

	local base = "chunk_" .. string.format("%03d", n) .. "_" .. tag .. "_" .. h
	S.chunks[#S.chunks + 1] = { n = n, tag = tag, size = #src, name = base,
		binary = isBinary(src), name2 = tostring(chunkname) }

	if isBinary(src) then
		S.saveRaw(base .. ".bin", src)
		S.save(base .. ".b64.txt", b64(src))
		S.save(base .. ".info.txt", "-- bytes passed to " .. tag .. "(" .. tostring(chunkname)
			.. ")\n-- size: " .. #src .. "\n-- isECR: " .. tostring(src:sub(1, 4) == "\27LUA")
			.. "\n-- HEX:\n" .. hexDump(src, 96) .. "\n")
		S.log("#" .. n .. " BINARY (" .. #src .. " bytes) -> " .. base .. ".bin")
	else
		S.save(base .. ".lua", src)
		S.log("#" .. n .. " TEXT (" .. #src .. " chars) -> " .. base .. ".lua")

		-- анализ исходника
		if S.cfg.analyze then
			local names, strs, blobs, total = scanLua(src)
			for _, s in ipairs(strs) do S.strings[#S.strings + 1] = s end
			for k, bl in ipairs(blobs) do
				S.save("vm_blobs/" .. base .. "_blob" .. k .. ".txt", bl)
			end
			local declared = declaredNames(src)
			local called, other = {}, {}
			for _, r in ipairs(names) do
				if not declared[r.name] and not globalExists(r.name) then
					if r.called then called[#called + 1] = r else other[#other + 1] = r end
				end
			end
			if #called > 0 or #other > 0 then
				local out = {}
				out[#out + 1] = "=== " .. base .. " (" .. total .. " chars) ==="
				if #called > 0 then
					out[#out + 1] = ">>> CALLED BUT MISSING (" .. #called .. "):"
					for _, r in ipairs(called) do
						out[#out + 1] = string.format("  %-26s line %-6d uses %d", r.name, r.line, r.count)
						out[#out + 1] = "      " .. r.ctx
					end
				end
				if #other > 0 then
					local nm = {}
					for _, r in ipairs(other) do nm[#nm + 1] = r.name end
					out[#out + 1] = "--- referenced only (" .. #other .. "): " .. table.concat(nm, ", ")
				end
				S.save("missing_globals.txt", table.concat(out, "\n") .. "\n")
				local cn = {}
				for _, r in ipairs(called) do cn[#cn + 1] = r.name end
				if #cn > 0 then
					S.log("MISSING-CALLED " .. base .. ": " .. table.concat(cn, ", "))
				end
			end
		end

		-- форматирование (читаемый вид)
		if S.cfg.format and n <= S.cfg.maxFormats then
			local job = function()
				local okF, pretty = pcall(formatLua, src)
				if okF and type(pretty) == "string" and #pretty > 0 then
					S.save(base .. ".pretty.lua", pretty)
					S.log("#" .. n .. " formatted -> " .. base .. ".pretty.lua")
				else
					S.log("formatter failed on #" .. n .. ": " .. tostring(pretty))
				end
			end
			if type(task) == "table" and type(task.spawn) == "function" then task.spawn(job) else job() end
		end

		if S.cfg.walkProtos and ok and type(compiled) == "function" then
			if type(task) == "table" and type(task.spawn) == "function" then
				task.spawn(function() pcall(walkFn, compiled, 0) end)
			else
				pcall(walkFn, compiled, 0)
			end
		end
	end

	if ok and type(compiled) == "function" and type(string.dump) == "function" then
		local dok, dumped = pcall(string.dump, compiled)
		if dok and type(dumped) == "string" and #dumped > 0 then
			S.saveRaw(base .. ".dump.bin", dumped)
			S.save(base .. ".dump.b64.txt", b64(dumped))
		end
	end

	if #S.outline > 0 then S.save("outline.txt", table.concat(S.outline, "\n")) end
	if #S.strings > 0 then S.save("strings.txt", table.concat(S.strings, "\n")) end
	S.log("report updated: " .. S.dir)
end

---------------------------------------------------------------------------
-- 11. СВИП ГЛОБАЛОВ (ловит payload, который выполнился мимо loadstring)
---------------------------------------------------------------------------
S.baseGlobals = {}
local function snapshot()
	local snap = {}
	for _, t in ipairs(envTargets()) do
		for k, v in pairs(t) do snap[tostring(k)] = v end
	end
	return snap
end
for k, v in pairs(snapshot()) do S.baseGlobals[k] = v end

function S.sweep()
	local found = {}
	for _, t in ipairs(envTargets()) do
		for k, v in pairs(t) do
			local key = tostring(k)
			if S.baseGlobals[key] == nil then found[key] = v end
		end
	end
	local lines = {}
	for key, v in pairs(found) do
		local kind = type(v)
		lines[#lines + 1] = key .. " = " .. kind
		if kind == "function" and type(string.dump) == "function" then
			local ok2, dumped = pcall(string.dump, v)
			if ok2 and type(dumped) == "string" then
				S.saveRaw("globals_after/" .. key:gsub("[^%w_]", "_") .. ".bin", dumped)
				S.save("globals_after/" .. key:gsub("[^%w_]", "_") .. ".b64.txt", b64(dumped))
			end
		elseif kind == "string" and #v > 1 then
			S.save("globals_after/" .. key:gsub("[^%w_]", "_") .. ".txt", v)
		elseif kind == "table" then
			local parts = {}
			for kk, vv in pairs(v) do
				if type(vv) == "string" and #vv > 1 and #parts < 40 then
					parts[#parts + 1] = tostring(kk) .. "=" .. string.format("%q", vv:sub(1, 60))
				end
			end
			if #parts > 0 then
				S.save("globals_after/" .. key:gsub("[^%w_]", "_") .. ".strings.txt",
					table.concat(parts, "\n"))
			end
		end
		S.baseGlobals[key] = v
	end
	if #lines > 0 then
		table.sort(lines)
		S.save("globals_after.txt", table.concat(lines, "\n"))
		S.log("sweep: " .. #lines .. " new globals -> globals_after.txt")
	end
	return #lines
end

---------------------------------------------------------------------------
-- 12. ОТЧЁТ
---------------------------------------------------------------------------
function S.buildReport()
	local out = {}
	out[#out + 1] = "=== VM-DUMP ==="
	out[#out + 1] = "folder: workspace/" .. tostring(S.dir)
	out[#out + 1] = "hooks: " .. hookCount .. "   chunks: " .. S.counter
	out[#out + 1] = ""
	out[#out + 1] = "=== HOOKS / API ==="
	for _, nm in ipairs({"loadstring","load","request","http_request","hookmetamethod",
		"newcclosure","getconstants","getprotos","getupvalues","setfenv","getfenv",
		"writefile","bit32","bit","unpack","newproxy","require","debug","buffer"}) do
		local v = rawget(genv, nm)
		if v == nil then v = rawget(_G, nm) end
		out[#out + 1] = string.format("  %-18s %s", nm, type(v))
	end
	out[#out + 1] = ""
	out[#out + 1] = "=== SHIMS ==="
	local keys = {}
	for k in pairs(S.shims) do keys[#keys + 1] = k end
	table.sort(keys)
	for _, k in ipairs(keys) do out[#out + 1] = string.format("  %-18s %s", k, S.shims[k]) end
	out[#out + 1] = ""
	out[#out + 1] = "=== CHUNKS ==="
	for _, c in ipairs(S.chunks) do
		out[#out + 1] = string.format("  #%d %s %s bytes=%s chunk=%s",
			c.n, c.tag, tostring(c.binary and "BINARY" or "TEXT"),
			tostring(c.size), tostring(c.name2))
	end
	if #S.logBuf > 0 then
		out[#out + 1] = ""
		out[#out + 1] = "=== LOG ==="
		for _, l in ipairs(S.logBuf) do out[#out + 1] = "  " .. l end
	end
	return table.concat(out, "\n")
end

---------------------------------------------------------------------------
-- 13. УСТАНОВКА
---------------------------------------------------------------------------
local function installAll()
	hookCount = 0
	install("loadstring", "loadstring")
	install("load", "load")
	patchHttp()
	installRequest("request", genv)
	installRequest("http_request", genv)
	local syn = rawget(genv, "syn")
	if type(syn) == "table" then
		installRequest("request", syn)
		installRequest("http_request", syn)
	end
	installEnvHooks()
	installShims()
	S.log("all hooks installed: " .. hookCount)

	if S.cfg.hookRemotes and type(hookmetamethod) == "function" then
		pcall(function()
			local want = {
				RemoteEvent = true, RemoteFunction = true,
				UnreliableRemoteEvent = true, BindableEvent = true,
			}
			local function hookOne(inst)
				local cn = inst.ClassName
				if S.remHooked[cn] then return end
				S.remHooked[cn] = true
				local h = function(self, ...)
					local m = getnamecallmethod()
					if m == "FireServer" or m == "InvokeServer" or m == "FireClient" then
						local parts = {}
						for k = 1, select("#", ...) do parts[#parts + 1] = tostring(select(k, ...)) end
						S.remoteLog[#S.remoteLog + 1] = string.format("%s:%s(%s)",
							inst:GetFullName(), m, table.concat(parts, ","))
						if #S.remoteLog > 2000 then table.remove(S.remoteLog, 1) end
						S.save("remotes_log.txt", table.concat(S.remoteLog, "\n"))
					end
					local base = S.remBase[cn]
					if type(base) == "function" then return base(self, ...) end
				end
				local ok2, prev = pcall(hookmetamethod, inst, "__namecall", h)
				if ok2 and type(prev) == "function" then S.remBase[cn] = baseOf(prev) end
			end
			for _, inst in ipairs(game:GetDescendants()) do
				if want[inst.ClassName] then hookOne(inst) end
			end
			game.DescendantAdded:Connect(function(inst)
				if want[inst.ClassName] then hookOne(inst) end
			end)
		end)
	end
	return hookCount
end

installAll()

if S.hasWrite then pcall(writefile, S.dir .. "/00_REPORT.txt", S.buildReport()) end

---------------------------------------------------------------------------
-- 14. РУЧНЫЕ КОМАНДЫ
---------------------------------------------------------------------------
genv.VMDUMP_STATUS = function()
	return string.format("dir=%s chunks=%d http=%d fns=%d hooks=%d",
		tostring(S.dir), S.counter, S.httpCount, S.walkCount, hookCount)
end

genv.VMDUMP_SWEEP = function()
	local n = S.sweep()
	print("[VMDump] sweep found " .. n .. " new globals")
	return n
end

genv.VMDUMP_FLUSH = function()
	if #S.outline > 0 then S.save("outline.txt", table.concat(S.outline, "\n")) end
	if #S.strings > 0 then S.save("strings.txt", table.concat(S.strings, "\n")) end
	if S.hasWrite then S.save("00_REPORT.txt", S.buildReport()) end
	print("[VMDump] " .. genv.VMDUMP_STATUS())
	return S.dir
end

genv.VMDUMP_RETRY = function()
	installAll()
	if S.hasWrite then S.save("00_REPORT.txt", S.buildReport()) end
	print("[VMDump] re-hooked: " .. genv.VMDUMP_STATUS())
end

genv.VMDUMP_FMT = function(src, name)
	if type(src) ~= "string" then return "need a string" end
	local pretty = formatLua(src)
	S.save((name or "manual") .. ".pretty.lua", pretty)
	return "ok " .. #pretty
end

print("======================================================")
print("  VM-DUMP v1 - RUNNING")
print("  folder: workspace/" .. S.dir)
print("  hooks: " .. hookCount)
print("  now run your loadstring / obfuscated script")
print("======================================================")
notify("VM-Dump", "Ready! " .. S.dir)
