-- [[ VANTA JNKIE Auto-Injector & HTTP Sniffer ]] --
local os_date = os.date("%Y-%m-%d_%H-%M-%S")
local base_folder = "shlushatel"
local session_folder = base_folder .. "/" .. os_date
local log_path = session_folder .. "/log.txt"

local function safeMakeFolder(path)
    if isfolder and not isfolder(path) then
        pcall(makefolder, path)
    elseif makefolder then
        pcall(makefolder, path)
    end
end

safeMakeFolder(base_folder)
safeMakeFolder(session_folder)

local dump_count = 0

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

local function dumpScript(code, source_info)
    dump_count = dump_count + 1
    local dump_filename = string.format("%s/dump_%d.lua", session_folder, dump_count)
    if writefile then
        pcall(writefile, dump_filename, "-- Source: " .. tostring(source_info) .. "\n\n" .. tostring(code))
    end
    return dump_filename
end

writeLog("=== JNKIE AUTO-INJECTOR & SNIFFER STARTED ===")
writeLog("Session directory: " .. session_folder)

-- AUTO-SET DUMMY KEY IF MISSING SO LOADER DOES NOT EARLY EXIT
if type(getgenv().SCRIPT_KEY) ~= "string" or getgenv().SCRIPT_KEY == "" then
    getgenv().SCRIPT_KEY = "DUMMY_SNIFFER_KEY_123"
    writeLog("[AUTO-FIX] SCRIPT_KEY was empty! Automatically set getgenv().SCRIPT_KEY = 'DUMMY_SNIFFER_KEY_123' to force HTTP request execution.")
else
    writeLog("Using existing SCRIPT_KEY: " .. tostring(getgenv().SCRIPT_KEY))
end

--------------------------------------------------------------------------------
-- 1. HOOK ALL EXECUTOR REQUEST FUNCTIONS
--------------------------------------------------------------------------------
local request_targets = {
    {name = "request", fn = request},
    {name = "http_request", fn = http_request},
    {name = "syn.request", fn = syn and syn.request},
    {name = "http.request", fn = http and http.request},
    {name = "fluxus.request", fn = fluxus and fluxus.request},
    {name = "krnl.request", fn = krnl and krnl.request},
}

local hooked_fns = {}

for _, item in ipairs(request_targets) do
    if item.fn and type(item.fn) == "function" and not hooked_fns[item.fn] and hookfunction then
        local original
        original = hookfunction(item.fn, function(options)
            if type(options) == "table" then
                local url = tostring(options.Url or options.url or "N/A")
                local method = tostring(options.Method or options.method or "GET")
                local body = tostring(options.Body or options.body or "")
                local headers = ""
                
                local req_headers = options.Headers or options.headers
                if type(req_headers) == "table" then
                    for k, v in pairs(req_headers) do
                        headers = headers .. "\n  " .. tostring(k) .. ": " .. tostring(v)
                    end
                end
                
                writeLog(string.format(
                    "[HTTP REQUEST OUTGOING (%s)]\nMethod: %s\nURL: %s\nHeaders:%s\nBody (Key/Payload):\n%s",
                    item.name, method, url, (headers ~= "" and headers or " None"), (body ~= "" and body or "<empty>")
                ))
                
                local response = original(options)
                
                if type(response) == "table" then
                    local status = tostring(response.StatusCode or response.StatusDescription or "200")
                    local resp_body = tostring(response.Body or response.body or "")
                    
                    local dumped_file = dumpScript(resp_body, "HTTP Response from " .. url .. " (Status: " .. status .. ")")
                    
                    writeLog(string.format(
                        "[HTTP RESPONSE INCOMING (%s)]\nURL: %s\nStatus: %s\nSaved Payload to: %s\nResponse Body:\n%s",
                        item.name, url, status, dumped_file, resp_body
                    ))
                end
                
                return response
            end
            return original(options)
        end)
        hooked_fns[item.fn] = true
        writeLog("Hooked function: " .. item.name)
    end
end

--------------------------------------------------------------------------------
-- 2. HOOK GAME HTTP METHODS
--------------------------------------------------------------------------------
if hookfunction then
    pcall(function()
        local orig_httpget
        orig_httpget = hookfunction(game.HttpGet, function(self, url, ...)
            writeLog(string.format("[game.HttpGet Call]\nURL: %s", tostring(url)))
            local res = orig_httpget(self, url, ...)
            if type(res) == "string" and #res > 0 then
                local dumped = dumpScript(res, "game.HttpGet: " .. tostring(url))
                writeLog(string.format("[game.HttpGet Response]\nURL: %s\nSaved to: %s", tostring(url), dumped))
            end
            return res
        end)
    end)
end

--------------------------------------------------------------------------------
-- 3. HOOK LOADSTRING
--------------------------------------------------------------------------------
if hookfunction and type(loadstring) == "function" then
    local old_loadstring
    old_loadstring = hookfunction(loadstring, function(code, chunkname)
        local source_info = chunkname or "loadstring_execution"
        local dumped_file = dumpScript(code, source_info)
        
        writeLog(string.format(
            "[LOADSTRING INTERCEPTED]\nChunk: %s\nLength: %d bytes\nSaved code to: %s\nPreview:\n%s",
            tostring(source_info), #tostring(code), dumped_file, tostring(code):sub(1, 300)
        ))
        
        return old_loadstring(code, chunkname)
    end)
end

writeLog("Hooks ready. Run your JNKIE loader now.")
