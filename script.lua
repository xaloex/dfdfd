-- [[ VANTA HTTP & Key Check Sniffer ]] --
local os_date = os.date("%Y-%m-%d_%H-%M-%S")
local base_folder = "shlushatel"
local session_folder = base_folder .. "/" .. os_date
local log_path = session_folder .. "/log.txt"

-- Ensure directories exist using standard executor FS API
if isfolder and not isfolder(base_folder) then
    makefolder(base_folder)
end

if isfolder and not isfolder(session_folder) then
    makefolder(session_folder)
elseif makefolder and not isfolder then
    pcall(makefolder, base_folder)
    pcall(makefolder, session_folder)
end

local function writeLog(text)
    local timestamp = os.date("[%Y-%m-%d %H:%M:%S] ")
    local entry = timestamp .. text .. "\n" .. string.rep("-", 80) .. "\n"
    
    if appendfile then
        pcall(appendfile, log_path, entry)
    elseif writefile and readfile then
        local current = ""
        pcall(function() current = readfile(log_path) end)
        pcall(writefile, log_path, current .. entry)
    elseif writefile then
        pcall(writefile, log_path, entry)
    end
    
    print("[SNIFFER] " .. text)
end

writeLog("=== SESSION STARTED ===")
writeLog("Listening for network requests and loadstring calls...")

-- 1. Hook Request Functions (request, http_request, syn.request, etc.)
local request_fns = {}
if type(request) == "function" then table.insert(request_fns, {name = "request", fn = request}) end
if type(http_request) == "function" then table.insert(request_fns, {name = "http_request", fn = http_request}) end
if type(syn) == "table" and type(syn.request) == "function" then table.insert(request_fns, {name = "syn.request", fn = syn.request}) end
if type(http) == "table" and type(http.request) == "function" then table.insert(request_fns, {name = "http.request", fn = http.request}) end

local hooked = {}

for _, item in ipairs(request_fns) do
    if not hooked[item.fn] and hookfunction then
        local old_fn
        old_fn = hookfunction(item.fn, function(options)
            if type(options) == "table" then
                local url = tostring(options.Url or options.url or "N/A")
                local method = tostring(options.Method or options.method or "GET")
                local body = tostring(options.Body or options.body or "")
                local headers = ""
                
                if type(options.Headers or options.headers) == "table" then
                    for k, v in pairs(options.Headers or options.headers) do
                        headers = headers .. "\n  " .. tostring(k) .. ": " .. tostring(v)
                    end
                end
                
                local log_msg = string.format(
                    "[HTTP REQUEST via %s]\nMethod: %s\nURL: %s\nHeaders:%s\nBody: %s",
                    item.name, method, url, (headers ~= "" and headers or " None"), (body ~= "" and body or " Empty")
                )
                
                writeLog(log_msg)
            end
            
            return old_fn(options)
        end)
        hooked[item.fn] = true
    end
end

-- 2. Hook game:HttpGet / game:HttpPost metamethods
if hookmetamethod then
    local old_namecall
    old_namecall = hookmetamethod(game, "__namecall", function(self, ...)
        local method = getnamecallmethod()
        if method == "HttpGet" or method == "HttpGetAsync" then
            local args = {...}
            local url = tostring(args[1])
            writeLog(string.format("[game:%s]\nURL: %s", method, url))
        elseif method == "HttpPost" or method == "HttpPostAsync" then
            local args = {...}
            local url = tostring(args[1])
            local data = tostring(args[2] or "")
            writeLog(string.format("[game:%s]\nURL: %s\nData: %s", method, url, data))
        end
        return old_namecall(self, ...)
    end)
end

-- 3. Hook loadstring to inspect dynamically executed code
if hookfunction and type(loadstring) == "function" then
    local old_loadstring
    old_loadstring = hookfunction(loadstring, function(code, chunkname)
        local snippet = tostring(code):sub(1, 500)
        writeLog(string.format("[LOADSTRING EXECUTED]\nChunk: %s\nCode Snippet (First 500 chars):\n%s", tostring(chunkname or "N/A"), snippet))
        return old_loadstring(code, chunkname)
    end)
end

writeLog("Hooks successfully installed. Execute your key-system script now.")
