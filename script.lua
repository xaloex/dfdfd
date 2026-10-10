-- [[ VANTA Deep Environment & Runtime Tracer (Crash-Proof) ]] --
local raw_sub = string.sub
local raw_match = string.match
local raw_find = string.find
local raw_format = string.format
local raw_rep = string.rep
local raw_tostring = tostring
local raw_pcall = pcall

local os_date = os.date("%Y-%m-%d_%H-%M-%S")
local base_folder = "shlushatel"
local session_folder = base_folder .. "/" .. os_date
local log_path = session_folder .. "/deep_trace.txt"

local function safeMakeFolder(path)
    if isfolder and not isfolder(path) then
        raw_pcall(makefolder, path)
    elseif makefolder then
        raw_pcall(makefolder, path)
    end
end

safeMakeFolder(base_folder)
safeMakeFolder(session_folder)

local function writeLog(text)
    local timestamp = os.date("[%Y-%m-%d %H:%M:%S] ")
    local entry = timestamp .. raw_tostring(text) .. "\n" .. raw_rep("-", 80) .. "\n"
    
    if appendfile then
        raw_pcall(appendfile, log_path, entry)
    elseif writefile and readfile then
        local current = ""
        raw_pcall(function() current = readfile(log_path) end)
        raw_pcall(writefile, log_path, current .. entry)
    elseif writefile then
        raw_pcall(writefile, log_path, entry)
    end
    
    print("[TRACER] " .. raw_tostring(text))
end

writeLog("=== DEEP TRACER & RUNTIME PROBER STARTED ===")
writeLog("Session directory: " .. session_folder)

--------------------------------------------------------------------------------
-- 1. SAFE ENVIRONMENT HOOK (No protected metatable crash)
--------------------------------------------------------------------------------
local env = (type(getgenv) == "function" and getgenv()) or _G

raw_pcall(function()
    if getrawmetatable and setreadonly then
        local mt = getrawmetatable(env)
        if mt then
            setreadonly(mt, false)
            local old_index = mt.__index
            local old_newindex = mt.__newindex
            
            mt.__index = function(t, k)
                if k == "SCRIPT_KEY" or (type(k) == "string" and raw_find(k, "KEY")) then
                    writeLog("[ENV READ] Key-related global read: " .. raw_tostring(k))
                end
                if type(old_index) == "function" then
                    return old_index(t, k)
                elseif type(old_index) == "table" then
                    return old_index[k]
                end
                return rawget(t, k)
            end
            
            mt.__newindex = function(t, k, v)
                writeLog(raw_format("[ENV WRITE] Global set: %s = %s", raw_tostring(k), raw_tostring(v)))
                if type(old_newindex) == "function" then
                    return old_newindex(t, k, v)
                elseif type(old_newindex) == "table" then
                    old_newindex[k] = v
                    return
                end
                rawset(t, k, v)
            end
            writeLog("Environment metatable hooked cleanly.")
        end
    end
end)

--------------------------------------------------------------------------------
-- 2. SAFE STRING OPERATIONS TRACE
--------------------------------------------------------------------------------
if hookfunction then
    raw_pcall(function()
        local old_match
        old_match = hookfunction(string.match, function(s, pattern, ...)
            local str = raw_tostring(s)
            local pat = raw_tostring(pattern)
            if raw_find(str, "http") or raw_find(str, "LDR") or raw_find(str, "jnkie") or raw_find(pat, "LDR") then
                writeLog(raw_format("[STRING.MATCH]\nString: %s\nPattern: %s", str, pat))
            end
            return old_match(s, pattern, ...)
        end)
        writeLog("Hooked string.match.")
    end)
end

--------------------------------------------------------------------------------
-- 3. NETWORK REQUESTS & RESPONSES TRACE
--------------------------------------------------------------------------------
local req_fns = {
    {name = "request", fn = request},
    {name = "http_request", fn = http_request},
    {name = "syn.request", fn = syn and syn.request},
    {name = "http.request", fn = http and http.request},
    {name = "fluxus.request", fn = fluxus and fluxus.request},
    {name = "krnl.request", fn = krnl and krnl.request},
}

for _, item in ipairs(req_fns) do
    if item.fn and type(item.fn) == "function" and hookfunction then
        raw_pcall(function()
            local old_fn
            old_fn = hookfunction(item.fn, function(options)
                if type(options) == "table" then
                    local url = raw_tostring(options.Url or options.url or "N/A")
                    local method = raw_tostring(options.Method or options.method or "GET")
                    local body = raw_tostring(options.Body or options.body or "")
                    local headers_str = ""
                    
                    local h = options.Headers or options.headers
                    if type(h) == "table" then
                        for k, v in pairs(h) do
                            headers_str = headers_str .. "\n  " .. raw_tostring(k) .. ": " .. raw_tostring(v)
                        end
                    end
                    
                    writeLog(raw_format(
                        "[NETWORK REQUEST via %s]\nMethod: %s\nURL: %s\nHeaders:%s\nBody:\n%s",
                        item.name, method, url, (headers_str ~= "" and headers_str or " None"), body
                    ))
                    
                    local res = old_fn(options)
                    
                    if type(res) == "table" then
                        local status = raw_tostring(res.StatusCode or "N/A")
                        local res_body = raw_tostring(res.Body or "")
                        
                        writeLog(raw_format(
                            "[NETWORK RESPONSE via %s]\nURL: %s\nStatus: %s\nLength: %d bytes\nBody:\n%s",
                            item.name, url, status, #res_body, res_body
                        ))
                    end
                    
                    return res
                end
                return old_fn(options)
            end)
            writeLog("Hooked network function: " .. item.name)
        end)
    end
end

--------------------------------------------------------------------------------
-- 4. LOADSTRING & CHUNK TRACE
--------------------------------------------------------------------------------
if hookfunction and type(loadstring) == "function" then
    raw_pcall(function()
        local old_loadstring
        old_loadstring = hookfunction(loadstring, function(code, chunkname)
            local c = raw_tostring(code)
            writeLog(raw_format(
                "[LOADSTRING INTERCEPTED]\nChunk: %s\nLength: %d bytes\nCode:\n%s",
                raw_tostring(chunkname or "N/A"), #c, c
            ))
            return old_loadstring(code, chunkname)
        end)
        writeLog("Hooked loadstring cleanly.")
    end)
end

writeLog("Crash-proof Deep Tracer active. Ready.")
