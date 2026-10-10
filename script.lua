-- [[ VANTA Deep Environment & Runtime Tracer ]] --
local os_date = os.date("%Y-%m-%d_%H-%M-%S")
local base_folder = "shlushatel"
local session_folder = base_folder .. "/" .. os_date
local log_path = session_folder .. "/deep_trace.txt"

local function safeMakeFolder(path)
    if isfolder and not isfolder(path) then
        pcall(makefolder, path)
    elseif makefolder then
        pcall(makefolder, path)
    end
end

safeMakeFolder(base_folder)
safeMakeFolder(session_folder)

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
    
    print("[TRACER] " .. text)
end

writeLog("=== DEEP TRACER & RUNTIME PROBER STARTED ===")
writeLog("Session directory: " .. session_folder)

--------------------------------------------------------------------------------
-- 1. TRACE STRING OPERATIONS (To catch obfuscated strings & hidden URLs)
--------------------------------------------------------------------------------
if hookfunction then
    pcall(function()
        local orig_sub = hookfunction(string.sub, function(s, i, j)
            local str = tostring(s)
            if #str > 15 and (str:find("http") or str:find("jnkie") or str:find("api") or str:find("key") or str:find("LDR")) then
                writeLog(string.format("[STRING.SUB TRACE]\nInput: %s\nRange: %s to %s", str, tostring(i), tostring(j)))
            end
            return orig_sub(s, i, j)
        end)
    end)
    
    pcall(function()
        local orig_match = hookfunction(string.match, function(s, pattern)
            local str = tostring(s)
            if str:find("http") or str:find("LDR") or str:find("jnkie") then
                writeLog(string.format("[STRING.MATCH TRACE]\nTarget: %s\nPattern: %s", str, tostring(pattern)))
            end
            return orig_match(s, pattern)
        end)
    end)
end

--------------------------------------------------------------------------------
-- 2. TRACE ALL ENVIRONMENT ACCESS (getgenv / getrenv / getfenv)
--------------------------------------------------------------------------------
local env = getgenv and getgenv() or _G
setmetatable(env, {
    __index = function(t, k)
        writeLog("[ENV READ] Global accessed: " .. tostring(k))
        return rawget(t, k)
    end,
    __newindex = function(t, k, v)
        writeLog(string.format("[ENV WRITE] Global set: %s = %s", tostring(k), tostring(v)))
        rawset(t, k, v)
    end
})

--------------------------------------------------------------------------------
-- 3. TRACE NETWORK REQUESTS & RESPONSES
--------------------------------------------------------------------------------
local req_fns = {
    {name = "request", fn = request},
    {name = "http_request", fn = http_request},
    {name = "syn.request", fn = syn and syn.request},
    {name = "http.request", fn = http and http.request},
}

for _, item in ipairs(req_fns) do
    if item.fn and type(item.fn) == "function" and hookfunction then
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
                    "[NETWORK REQUEST via %s]\nMethod: %s\nURL: %s\nHeaders:%s\nBody:\n%s",
                    item.name, method, url, (headers_str ~= "" and headers_str or " None"), body
                ))
                
                local res = old_fn(options)
                
                if type(res) == "table" then
                    local status = tostring(res.StatusCode or "N/A")
                    local res_body = tostring(res.Body or "")
                    
                    writeLog(string.format(
                        "[NETWORK RESPONSE via %s]\nURL: %s\nStatus: %s\nLength: %d bytes\nBody:\n%s",
                        item.name, url, status, #res_body, res_body
                    ))
                end
                
                return res
            end
            return old_fn(options)
        end)
        writeLog("Hooked network function: " .. item.name)
    end
end

--------------------------------------------------------------------------------
-- 4. TRACE LOADSTRING & DUMP ALL EXECUTED CODE
--------------------------------------------------------------------------------
if hookfunction and type(loadstring) == "function" then
    local old_loadstring
    old_loadstring = hookfunction(loadstring, function(code, chunkname)
        local c = tostring(code)
        writeLog(string.format(
            "[LOADSTRING INTERCEPTED]\nChunk: %s\nLength: %d bytes\nCode:\n%s",
            tostring(chunkname or "N/A"), #c, c
        ))
        return old_loadstring(code, chunkname)
    end)
    writeLog("Hooked loadstring for full code tracing.")
end

writeLog("Deep Tracer active. Run your loadstring now.")
