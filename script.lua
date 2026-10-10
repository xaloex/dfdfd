-- [[ VANTA JNKIE Interceptor & Response Spoofer ]] --
local os_date = os.date("%Y-%m-%d_%H-%M-%S")
local base_folder = "shlushatel"
local session_folder = base_folder .. "/" .. os_date
local log_path = session_folder .. "/log.txt"

-- НАСТРОЙКИ ЭМУЛЯЦИИ / ПОДМЕНЫ
getgenv().SPOOF_JNKIE_KEY = false -- Поставь true, если хочешь вернуть фейковый 200 OK
getgenv().SPOOF_SCRIPT_URL = "https://raw.githubusercontent.com/site/main/script.lua" -- Ссылка на замену (если нужно)

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

writeLog("=== JNKIE SPOOFER & SNIFFER STARTED ===")
writeLog("Session directory: " .. session_folder)

if type(getgenv().SCRIPT_KEY) ~= "string" or getgenv().SCRIPT_KEY == "" then
    getgenv().SCRIPT_KEY = "DUMMY_SNIFFER_KEY"
end

--------------------------------------------------------------------------------
-- 1. HOOK REQUEST & RESPONSE SPOOFING
--------------------------------------------------------------------------------
local request_targets = {
    {name = "request", fn = request},
    {name = "http_request", fn = http_request},
    {name = "syn.request", fn = syn and syn.request},
    {name = "http.request", fn = http and http.request},
}

for _, item in ipairs(request_targets) do
    if item.fn and type(item.fn) == "function" and hookfunction then
        local original
        original = hookfunction(item.fn, function(options)
            if type(options) == "table" then
                local url = tostring(options.Url or options.url or "N/A")
                local method = tostring(options.Method or options.method or "GET")
                local body = tostring(options.Body or options.body or "")
                
                writeLog(string.format("[OUTGOING REQUEST (%s)]\nMethod: %s\nURL: %s\nBody: %s", item.name, method, url, body))
                
                -- Если включен споофинг и это запрос проверки ключа JNKIE
                if getgenv().SPOOF_JNKIE_KEY and url:find("jnkie.com/api/v1/luascripts/delivery") then
                    writeLog("[SPOOFER INTERCEPTED] Returning fake 200 OK with payload URL...")
                    return {
                        StatusCode = 200,
                        StatusDescription = "OK",
                        Headers = {["Content-Type"] = "text/plain"},
                        Body = getgenv().SPOOF_SCRIPT_URL
                    }
                end
                
                local response = original(options)
                
                if type(response) == "table" then
                    local status = tostring(response.StatusCode or "200")
                    local resp_body = tostring(response.Body or "")
                    
                    local dumped_file = dumpScript(resp_body, "HTTP Response from " .. url)
                    writeLog(string.format("[INCOMING RESPONSE (%s)]\nURL: %s\nStatus: %s\nDumped: %s\nBody:\n%s", 
                        item.name, url, status, dumped_file, resp_body:sub(1, 300)))
                end
                
                return response
            end
            return original(options)
        end)
    end
end

--------------------------------------------------------------------------------
-- 2. HOOK LOADSTRING
--------------------------------------------------------------------------------
if hookfunction and type(loadstring) == "function" then
    local old_loadstring
    old_loadstring = hookfunction(loadstring, function(code, chunkname)
        local dumped_file = dumpScript(code, chunkname or "loadstring")
        writeLog(string.format("[LOADSTRING DUMPED]\nLength: %d bytes\nFile: %s", #tostring(code), dumped_file))
        return old_loadstring(code, chunkname)
    end)
end

writeLog("Hooks deployed.")
