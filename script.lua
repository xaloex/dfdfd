-- [[ VANTA Maximum HTTP & Loadstring Sniffer / Dumper ]] --
local os_date = os.date("%Y-%m-%d_%H-%M-%S")
local base_folder = "shlushatel"
local session_folder = base_folder .. "/" .. os_date
local log_path = session_folder .. "/log.txt"

-- Safe FS creation
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

writeLog("=== MAXIMUM SNIFFER SESSION STARTED ===")
writeLog("Session output directory: " .. session_folder)

-- Helper to safely clone functions if available
local clone = clonefunction or function(f) return f end

--------------------------------------------------------------------------------
-- 1. HOOK ALL EXECUTOR REQUEST FUNCTIONS (Direct & Aliases)
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
                    "[REQUEST OUTGOING via %s]\nMethod: %s\nURL: %s\nHeaders:%s\nBody:\n%s",
                    item.name, method, url, (headers ~= "" and headers or " None"), (body ~= "" and body or "<empty>")
                ))
                
                local response = original(options)
                
                if type(response) == "table" then
                    local status = tostring(response.StatusCode or response.StatusDescription or "200")
                    local resp_body = tostring(response.Body or response.body or "")
                    
                    local resp_dump_file = ""
                    if #resp_body > 300 then
                        resp_dump_file = dumpScript(resp_body, "HTTP Response from " .. url)
                    end
                    
                    writeLog(string.format(
                        "[REQUEST RESPONSE via %s]\nURL: %s\nStatus: %s\nBody Length: %d bytes%s\nBody Preview:\n%s",
                        item.name, url, status, #resp_body, 
                        (resp_dump_file ~= "" and (" (Full saved to " .. resp_dump_file .. ")") or ""),
                        (#resp_body > 300 and resp_body:sub(1, 300) .. "..." or resp_body)
                    ))
                end
                
                return response
            end
            return original(options)
        end)
        hooked_fns[item.fn] = true
        writeLog("Successfully hooked executor function: " .. item.name)
    end
end

--------------------------------------------------------------------------------
-- 2. HOOK DIRECT GAME METHODS (game.HttpGet & game.HttpPost)
--------------------------------------------------------------------------------
if hookfunction then
    pcall(function()
        local orig_httpget
        orig_httpget = hookfunction(game.HttpGet, function(self, url, ...)
            writeLog(string.format("[game.HttpGet Direct Call]\nURL: %s", tostring(url)))
            local res = orig_httpget(self, url, ...)
            if type(res) == "string" and #res > 0 then
                local dumped = dumpScript(res, "game.HttpGet: " .. tostring(url))
                writeLog(string.format("[game.HttpGet Response]\nURL: %s\nSaved to: %s\nPreview:\n%s", tostring(url), dumped, res:sub(1, 300)))
            end
            return res
        end)
        writeLog("Hooked game.HttpGet directly.")
    end)

    pcall(function()
        local orig_httppost
        orig_httppost = hookfunction(game.HttpPost, function(self, url, data, ...)
            writeLog(string.format("[game.HttpPost Direct Call]\nURL: %s\nData:\n%s", tostring(url), tostring(data)))
            local res = orig_httppost(self, url, data, ...)
            if type(res) == "string" and #res > 0 then
                local dumped = dumpScript(res, "game.HttpPost: " .. tostring(url))
                writeLog(string.format("[game.HttpPost Response]\nURL: %s\nSaved to: %s\nPreview:\n%s", tostring(url), dumped, res:sub(1, 300)))
            end
            return res
        end)
        writeLog("Hooked game.HttpPost directly.")
    end)
end

--------------------------------------------------------------------------------
-- 3. HOOK __namecall METAMETHOD FOR GAME INSTANCES
--------------------------------------------------------------------------------
if hookmetamethod then
    local old_namecall
    old_namecall = hookmetamethod(game, "__namecall", function(self, ...)
        local method = getnamecallmethod()
        if method == "HttpGet" or method == "HttpGetAsync" then
            local args = {...}
            local url = tostring(args[1])
            writeLog(string.format("[__namecall %s]\nURL: %s", method, url))
        elseif method == "HttpPost" or method == "HttpPostAsync" then
            local args = {...}
            local url = tostring(args[1])
            local data = tostring(args[2] or "")
            writeLog(string.format("[__namecall %s]\nURL: %s\nData:\n%s", method, url, data))
        end
        return old_namecall(self, ...)
    end)
    writeLog("Hooked __namecall metamethod.")
end

--------------------------------------------------------------------------------
-- 4. HOOK LOADSTRING (Full dumper without truncation)
--------------------------------------------------------------------------------
if hookfunction and type(loadstring) == "function" then
    local old_loadstring
    old_loadstring = hookfunction(loadstring, function(code, chunkname)
        local source_info = chunkname or "loadstring_call"
        local dumped_file = dumpScript(code, source_info)
        
        writeLog(string.format(
            "[LOADSTRING INTERCEPTED]\nChunk: %s\nLength: %d bytes\nSaved full code to: %s\nCode Head (First 300 chars):\n%s",
            tostring(source_info), #tostring(code), dumped_file, tostring(code):sub(1, 300)
        ))
        
        return old_loadstring(code, chunkname)
    end)
    writeLog("Hooked loadstring completely with full dump support.")
end

writeLog("All hooks deployed successfully. Ready for script execution.")
