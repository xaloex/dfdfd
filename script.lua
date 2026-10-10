-- [[ VANTA Robust Network & Loadstring Sniffer ]] --
local os_date = os.date("%Y-%m-%d_%H-%M-%S")
local base_folder = "shlushatel"
local session_folder = base_folder .. "/" .. os_date
local log_path = session_folder .. "/log.txt"

-- Safe directory creation
if isfolder and not isfolder(base_folder) then pcall(makefolder, base_folder) end
if isfolder and not isfolder(session_folder) then pcall(makefolder, session_folder) end
if makefolder and not isfolder then
    pcall(makefolder, base_folder)
    pcall(makefolder, session_folder)
end

local dump_count = 0
local in_log = false

local function writeLog(text)
    if in_log then return end
    in_log = true
    
    local success, err = pcall(function()
        local timestamp = os.date("[%Y-%m-%d %H:%M:%S] ")
        local entry = timestamp .. tostring(text) .. "\n" .. string.rep("-", 80) .. "\n"
        
        if appendfile then
            appendfile(log_path, entry)
        elseif writefile and readfile then
            local current = ""
            pcall(function() current = readfile(log_path) end)
            writefile(log_path, current .. entry)
        elseif writefile then
            writefile(log_path, entry)
        end
        
        print("[SNIFFER] " .. tostring(text))
    end)
    
    in_log = false
end

local function dumpScript(code, source_info)
    dump_count = dump_count + 1
    local dump_filename = string.format("%s/dump_%d.lua", session_folder, dump_count)
    if writefile then
        pcall(writefile, dump_filename, "-- Source: " .. tostring(source_info) .. "\n\n" .. tostring(code))
    end
    return dump_filename
end

writeLog("=== SNIFFER INITIALIZED ===")
writeLog("Session directory: " .. session_folder)

-- Check SCRIPT_KEY
local env = (type(getgenv) == "function" and getgenv()) or _G
if type(env.SCRIPT_KEY) ~= "string" or env.SCRIPT_KEY == "" then
    env.SCRIPT_KEY = "DUMMY_AUTO_KEY"
    writeLog("Set default env.SCRIPT_KEY = 'DUMMY_AUTO_KEY'")
else
    writeLog("Current SCRIPT_KEY: " .. tostring(env.SCRIPT_KEY))
end

--------------------------------------------------------------------------------
-- 1. HOOK EXECUTOR HTTP REQUESTS (Outgoing & Incoming)
--------------------------------------------------------------------------------
local request_fns = {
    {name = "request", fn = request},
    {name = "http_request", fn = http_request},
    {name = "syn.request", fn = syn and syn.request},
    {name = "http.request", fn = http and http.request},
    {name = "fluxus.request", fn = fluxus and fluxus.request},
    {name = "krnl.request", fn = krnl and krnl.request},
}

local hooked = {}

for _, item in ipairs(request_fns) do
    if item.fn and type(item.fn) == "function" and not hooked[item.fn] and hookfunction then
        local old_fn
        old_fn = hookfunction(item.fn, function(options)
            if type(options) == "table" then
                local url = tostring(options.Url or options.url or "N/A")
                local method = tostring(options.Method or options.method or "GET")
                local body = tostring(options.Body or options.body or "")
                local headers_str = ""
                
                local h = options.Headers or options.headers
                if type(h) == "table" then
                    for k, v in pairs(h) do
                        headers_str = headers_str .. "\n  " .. tostring(k) .. ": " .. tostring(v)
                    end
                end
                
                writeLog(string.format(
                    "[HTTP OUTGOING (%s)]\nMethod: %s\nURL: %s\nHeaders:%s\nBody:\n%s",
                    item.name, method, url, (headers_str ~= "" and headers_str or " None"), body
                ))
                
                local res = old_fn(options)
                
                if type(res) == "table" then
                    local status = tostring(res.StatusCode or res.StatusDescription or "N/A")
                    local res_body = tostring(res.Body or res.body or "")
                    
                    local dumped_file = dumpScript(res_body, "HTTP Response from " .. url .. " (Status: " .. status .. ")")
                    
                    writeLog(string.format(
                        "[HTTP INCOMING (%s)]\nURL: %s\nStatus: %s\nSaved to: %s\nBody Length: %d bytes\nPreview:\n%s",
                        item.name, url, status, dumped_file, #res_body,
                        (#res_body > 300 and res_body:sub(1, 300) .. "..." or res_body)
                    ))
                end
                
                return res
            end
            return old_fn(options)
        end)
        hooked[item.fn] = true
        writeLog("Hooked request function: " .. item.name)
    end
end

--------------------------------------------------------------------------------
-- 2. HOOK GAME HTTP METHODS
--------------------------------------------------------------------------------
if hookfunction then
    pcall(function()
        local old_httpget
        old_httpget = hookfunction(game.HttpGet, function(self, url, ...)
            writeLog("[game.HttpGet Direct]\nURL: " .. tostring(url))
            local res = old_httpget(self, url, ...)
            if type(res) == "string" and #res > 0 then
                local dumped = dumpScript(res, "game.HttpGet: " .. tostring(url))
                writeLog("[game.HttpGet Response Saved]\nFile: " .. dumped)
            end
            return res
        end)
    end)
end

if hookmetamethod then
    pcall(function()
        local old_namecall
        old_namecall = hookmetamethod(game, "__namecall", function(self, ...)
            local method = getnamecallmethod()
            if method == "HttpGet" or method == "HttpGetAsync" then
                local args = {...}
                writeLog("[game:HttpGet]\nURL: " .. tostring(args[1]))
            elseif method == "HttpPost" or method == "HttpPostAsync" then
                local args = {...}
                writeLog("[game:HttpPost]\nURL: " .. tostring(args[1]) .. "\nData: " .. tostring(args[2] or ""))
            end
            return old_namecall(self, ...)
        end)
        writeLog("Hooked game __namecall.")
    end)
end

--------------------------------------------------------------------------------
-- 3. HOOK LOADSTRING (Full Dump)
--------------------------------------------------------------------------------
if hookfunction and type(loadstring) == "function" then
    pcall(function()
        local old_loadstring
        old_loadstring = hookfunction(loadstring, function(code, chunkname)
            local dumped_file = dumpScript(code, chunkname or "loadstring")
            writeLog(string.format(
                "[LOADSTRING DUMPED]\nFile: %s\nLength: %d bytes\nPreview:\n%s",
                dumped_file, #tostring(code), tostring(code):sub(1, 300)
            ))
            return old_loadstring(code, chunkname)
        end)
        writeLog("Hooked loadstring cleanly.")
    end)
end

writeLog("Ready. Clean and fully isolated.")
