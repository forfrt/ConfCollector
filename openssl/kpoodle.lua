

local socket=agent.require "socket"
local ssl=agent.require "ssl"

function checkSSLVersion(version)
    ctx_new(version)
    return nil
    
end

function checkAll()
    return checkSSLVersion("SSLv3"), checkSSLVersion("SSLV2"), checkSSLVersion("SSLV23"), checkSSLVersion("TLSV1")



end

function main(ip, port)
    print("Connecting...")
    local target, errorMsg=socket.connect(ip, port)
    if not target then
        print(errorMsg)
    end

    print("Checking...")
    local ssl3, ssl2, ssl23, tls=checkALL()
    target:close()
end
