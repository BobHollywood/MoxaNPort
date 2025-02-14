-- Dissector for various related Moxa protocols:
-- - CONF protocol on UDP/4800, for configuring a device
-- - CTRL protocol on TCP/966 to 981, for controlling a serial stream
--
-- TODO ------------------------------------------------------------------------------------------:
-- Port 4900, for firmware upgrade
-- Port 950 to 965, data port, except 982 to 997 (NPort-6610/6650-32 rackmount servers)
-- Port 9988 to 1013(NPort-6610/6650-32 rackmount servers) like CTRL port
-- Older models (DE-311/211/30X/33x) may also use port 1029 instead of 4800.
--

moxa_conf = Proto("moxa_conf", "MOXA_CONF")
moxa_ctrl = Proto("moxa_ctrl", "MOXA_CTRL")

function append_pinfo(pinfo, str)
    local info = tostring(pinfo.cols.info)
    if info == "" then
        pinfo.cols.info = str
    else
        pinfo.cols.info = string.format("%s, %s", info, str)
    end
end

-----------------------------------------------------------------------------------------------------------------------------------
-- MOXA "CONF" protocol

local cmds_map = {
    [0x01] = "Ident",
    [0x10] = "Identify",
    --[0x14] = "Get Server Name / Netstat",
    [0x16] = "Get Product Details",
    [0x1A] = "Date/Time",
    [0x1B] = "?",
    --[0x1E] = "Unlock2",
    [0x21] = "Get IP Address",
    [0x22] = "Get Netmask",
    [0x23] = "Get Default Gateway",
    [0x25] = "Get Autoreport Configuration",
    [0x26] = "Get Network Configuration",
    [0x27] = "Get DNS Configuration",
    [0x28] = "Get SNMP Configuration",
    [0x4D] = "Get Operation Settings",
    [0x4F] = "Get Port Settings",
    [0x29] = "Get Email Configuration",
    [0x51] = "Get Accessible IP Settings",
    [0x52] = "Get Event Type Settings",
   -- [0x2C] = "All creds",
}

local reqrsp_map = {
    [0] = "REQ",
    [1] = "RSP",
}

local eventtype_map = {
    [0] = "Disabled",
    [1] = "Enabled",
}


local mc_coldstarttrap_f    = ProtoField.new("Cold Start Trap",         "mconf.coldstarttrap",     ftypes.UINT8,    eventtype_map, base.DEC, 0x01)
local mc_warmstarttrap_f    = ProtoField.new("Warm Start Trap",         "mconf.warmstarttrap",     ftypes.UINT8,    eventtype_map, base.DEC, 0x02)
local mc_authfailuretrap_f  = ProtoField.new("Auth Failure Trap",       "mconf.authfailuretrap",   ftypes.UINT8,    eventtype_map, base.DEC, 0x04)
local mc_coldstartmail_f    = ProtoField.new("Cold Start Mail",         "mconf.coldstartmail",     ftypes.UINT8,    eventtype_map, base.DEC, 0x01)
local mc_warmstartmail_f    = ProtoField.new("Warm Start Mail",         "mconf.warmstartmail",     ftypes.UINT8,    eventtype_map, base.DEC, 0x02)
local mc_authfailuremail_f  = ProtoField.new("Auth Failure Mail",       "mconf.authfailuremail",   ftypes.UINT8,    eventtype_map, base.DEC, 0x04)
local mc_ipaddrchangemail_f = ProtoField.new("IP Address Change Mail",  "mconf.ipaddrchangemail",  ftypes.UINT8,    eventtype_map, base.DEC, 0x08)
local mc_pwchangemail_f     = ProtoField.new("Password Change Mail",    "mconf.pwchangemail",      ftypes.UINT8,    eventtype_map, base.DEC, 0x10)

local mc_reqrsp_f            = ProtoField.new("Req",                    "mconf.req",               ftypes.UINT8,    reqrsp_map, base.DEC, 0x80, "Req/Rsp")
local mc_cmd_f               = ProtoField.new("Command",                "mconf.cmd",               ftypes.UINT8,    cmds_map, base.HEX,   0x7F, "Command")
local mc_unknown_f           = ProtoField.new("Unknown",                "mconf.unknown",           ftypes.BYTES,    nil, base.DOT)
local mc_len_f               = ProtoField.new("Length",                 "mconf.len",               ftypes.INT16,    nil, base.DEC)
local mc_productline_f       = ProtoField.new("Productline",            "mconf.productline",       ftypes.UINT16,   nil, base.HEX)
local mc_model_f             = ProtoField.new("Model",                  "mconf.model",             ftypes.UINT16,   nil, base.HEX)
local mc_macaddr_f           = ProtoField.new("MAC Address",            "mconf.mac",               ftypes.BYTES,    nil, base.COLON)
local mc_ipaddr_f            = ProtoField.new("IP Address",             "mconf.ipaddr",            ftypes.IPv4,     nil, base.NONE)
local mc_netmask_f           = ProtoField.new("Netmask",                "mconf.netmask",           ftypes.IPv4,     nil, base.NONE)
local mc_defaultgateway_f    = ProtoField.new("Default Gateway",        "mconf.defgateway",        ftypes.IPv4,     nil, base.NONE)
local mc_swversion_f         = ProtoField.new("Software Version",       "mconf.swversion",         ftypes.UINT16,   nil, base.DEC)
local mc_serialnum_f         = ProtoField.new("Serial Number",          "mconf.serialnum",         ftypes.UINT16,   nil, base.DEC)
local mc_hostname_f          = ProtoField.new("Hostname",               "mconf.hostname",          ftypes.STRING,   nil, base.ASCII)
local mc_familyname_f        = ProtoField.new("Familyname",             "mconf.familyname",        ftypes.STRING,   nil, base.ASCII)

local mc_dns_f               = ProtoField.new("DNS Server",             "mconf.ds",                ftypes.IPv4,     nil, base.NONE)
local mc_bitrate_f           = ProtoField.new("Bitrate",                "mconf.bitrate",           ftypes.UINT32,   nil, base.DEC)

local mc_controlport_f       = ProtoField.new("Control Port",           "mconf.controlport",       ftypes.UINT16,   nil, base.DEC)
local mc_dataport_f          = ProtoField.new("Data Port",              "mconf.dataport",          ftypes.UINT16,   nil, base.DEC)
local mc_mailserver_f        = ProtoField.new("Mail Server",            "mconf.mailserver",        ftypes.STRING,   nil, base.ASCII)
local mc_mailsender_f        = ProtoField.new("From E-Mail",            "mconf.mailsender",        ftypes.STRING,   nil, base.ASCII)
local mc_mailaddress_f       = ProtoField.new("E-mail Address",         "mconf.mailaddress",       ftypes.STRING,   nil, base.ASCII)

local mc_autoreportaddr_f    = ProtoField.new("Autoreport address",     "mconf.autoreportaddress", ftypes.STRING,   nil, base.ASCII)
local mc_autoreportport_f    = ProtoField.new("Autoreport port",        "mconf.autoreportport",    ftypes.UINT16,   nil, base.DEC)
local mc_autoreporttimeout_f = ProtoField.new("Autoreport timeout",     "mconf.autoreporttimeout", ftypes.UINT16,   nil, base.DEC)
local mc_snmpcommunity_f     = ProtoField.new("SNMP Community Name",    "mconf.snmpcommunity",     ftypes.BYTES,    nil, base.COLON)
local mc_snmpcontact_f       = ProtoField.new("SNMP Contact",           "mconf.snmpcontact",       ftypes.STRING,   nil, base.ASCII)
local mc_snmplocation_f      = ProtoField.new("SNMP Location",          "mconf.snmplocation",      ftypes.STRING,   nil, base.ASCII)
local mc_snmptrapserver_f    = ProtoField.new("SNMP Trap Server",       "mconf.snmptrapserver",    ftypes.STRING,   nil, base.ASCII)

local mc_enabled_f           = ProtoField.new("Enabled",                "mconf.enabled",           ftypes.UINT32,   nil, base.DEC)
local mc_delimiter1_f        = ProtoField.new("Delimiter1",             "mconf.delimiter1",        ftypes.UINT8,    nil, base.HEX)
local mc_delimiter2_f        = ProtoField.new("Delimiter2",             "mconf.delimiter2",        ftypes.UINT8,    nil, base.HEX)
local mc_forcetransmit_f     = ProtoField.new("Force Transmit",         "mconf.forcetransmit",     ftypes.UINT16,   nil, base.DEC)


moxa_conf.fields = {
    mc_reqrsp_f,
    mc_cmd_f,
    mc_unknown_f,
    mc_len_f,
    mc_productline_f,
    mc_model_f,
    mc_macaddr_f,
    mc_ipaddr_f,
    mc_netmask_f,
    mc_dnsgateway_f,
    mc_defaultgateway_f,
    mc_swversion_f,
    mc_serialnum_f,
    mc_hostname_f,
    mc_familyname_f,
    mc_dns_f,
    mc_bitrate_f,
    mc_controlport_f,
    mc_dataport_f,
    mc_mailserver_f,
    mc_mailsender_f,
    mc_mailaddress_f,
    mc_autoreportaddr_f,
    mc_autoreportport_f,
    mc_autoreporttimeout_f,
    mc_snmpcommunity_f,
    mc_snmpcontact_f,
    mc_snmplocation_f,
    mc_snmptrapserver_f,
    mc_enabled_f,
    mc_delimiter1_f,
    mc_delimiter2_f,
    mc_forcetransmit_f,

    mc_coldstartmail_f,
    mc_warmstartmail_f,
    mc_authfailuremail_f,
    mc_ipaddrchangemail_f,
    mc_pwchangemail_f,

    mc_coldstarttrap_f,
    mc_warmstarttrap_f,
    mc_authfailuretrap_f,

}

function heur_dissect_moxa_conf(buffer, pinfo, tree)
    if buffer:len() < 8 then return false end

    if pinfo.dst_port ~= 4800 then return false end

    local offset = 0
    -- Check length matches TODO

    pinfo.conversation = moxa_conf
    moxa_conf.dissector(buffer, pinfo, tree)
    return true
end

function moxa_conf.dissector(buffer, pinfo, tree)
    if buffer:len() < 8 then return false end

    pinfo.cols.protocol = "MOXA_CONF"
    pinfo.cols.info = ""
    local pdu = tree:add(moxa_conf, buffer)

    local offset = 0
    local is_rsp = false
    local cmd = buffer(offset, 1):uint()
    if bit.band(cmd, 0x80) == 0x80 then
        append_pinfo(pinfo, string.format("[RSP %02X]", cmd))
        is_rsp = true
    else
        append_pinfo(pinfo, string.format("[REQ %02X]", cmd))
    end
    local cmdname = cmds_map[bit.band(cmd, 0x7F)]
    if cmdname ~= nil then
        append_pinfo(pinfo, cmdname)
    end
    pdu:add(mc_reqrsp_f, buffer(offset, 1))
    pdu:add(mc_cmd_f, buffer(offset, 1))
    offset = offset + 1

    pdu:add(mc_unknown_f, buffer(offset, 1)) -- Some rsp's have 0x04 here
    offset = offset + 1

    pdu:add(mc_len_f, buffer(offset, 2))
    offset = offset + 2

    pdu:add(mc_unknown_f, buffer(offset, 4))
    offset = offset + 4

    if is_rsp == false then
        if cmd == 0x01 then
            -- Nothing else follows
        elseif cmd >= 0x10 and cmd <= 0x7F then
            local productline = buffer(offset, 2):le_uint()
            pdu:add_le(mc_productline_f, buffer(offset, 2), productline, string.format("Productline: %x", productline))
            offset = offset + 2

            pdu:add(mc_unknown_f, buffer(offset, 2))
            offset = offset + 2

            local model = buffer(offset, 2):le_uint()
            pdu:add_le(mc_model_f, buffer(offset, 2), model, string.format("Model: %x", model))
            offset = offset + 2

            pdu:add_le(mc_macaddr_f, buffer(offset, 6))
            offset = offset + 6

            -- Some commands have additional fields
            if cmd == 0x26 then
                pdu:add(mc_unknown_f, buffer(offset, 2))
                offset = offset + 2
            elseif cmd == 0x28 then
                pdu:add(mc_unknown_f, buffer(offset, 2))
                offset = offset + 2

                pdu:add_le(mc_model_f, buffer(offset, 2))
                offset = offset + 2

                pdu:add_le(mc_macaddr_f, buffer(offset, 6))
                offset = offset + 6
            end
        end
    else
        -- Responses always start the same way
        local productline = buffer(offset, 2):le_uint()
        pdu:add_le(mc_productline_f, buffer(offset, 2), productline, string.format("Productline: %x", productline))
        offset = offset + 2

        pdu:add_le(mc_unknown_f, buffer(offset, 2))
        offset = offset + 2

        local model = buffer(offset, 2):le_uint()
        pdu:add_le(mc_model_f, buffer(offset, 2), model, string.format("Model: %x", model))
        offset = offset + 2

        pdu:add_le(mc_macaddr_f, buffer(offset, 6)) -- Again!
        offset = offset + 6

        if cmd == 0x81 then
            pdu:add(mc_ipaddr_f, buffer(offset, 4))
            offset = offset + 4
        elseif cmd == 0x82 then
            -- Nothing follows
        elseif cmd >= 0x85 and cmd <= 0x8F then
            -- Nothing follows
        elseif cmd == 0x90 then
            append_pinfo(pinfo, "Hostname: ".. buffer(offset, 40):string())
            pdu:add(mc_hostname_f, buffer(offset, 40))
            offset = offset + 40
        elseif cmd == 0x91 then
            pdu:add_le(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
            pdu:add(mc_familyname_f, buffer(offset, 32))
            offset = offset + 32
            pdu:add_le(mc_unknown_f, buffer(offset, 12))
            offset = offset + 12
        elseif cmd == 0x92 then
            pdu:add_le(mc_unknown_f, buffer(offset, 2))
            offset = offset + 2
        elseif cmd == 0x93 then
            -- Nothing follows
        elseif cmd == 0x94 then
            pdu:add_le(mc_unknown_f, buffer(offset, 20))
            offset = offset + 20
        elseif cmd == 0x95 then
            -- Nothing follows
        elseif cmd == 0x97 then
            -- Nothing follows
        elseif cmd == 0x98 then
            -- Nothing follows
        elseif cmd == 0x99 then
            pdu:add_le(mc_unknown_f, buffer(offset, 1))
            offset = offset + 1
        elseif cmd == 0x9A then
            pdu:add_le(mc_unknown_f, buffer(offset, 16))
            offset = offset + 16
        elseif cmd == 0x9B then
            pdu:add_le(mc_unknown_f, buffer(offset, 40))
            offset = offset + 40
        elseif cmd == 0x9C then
            pdu:add_le(mc_unknown_f, buffer(offset, 8))
            offset = offset + 8
        elseif cmd == 0x9D then
            pdu:add_le(mc_unknown_f, buffer(offset, 20))
            offset = offset + 208
        elseif cmd == 0x9E then
            -- Nothing follows
        elseif cmd == 0x9F then
            -- Nothing follows
        elseif cmd == 0xA0 then
            -- Nothing follows
        elseif cmd == 0xA1 then
            pdu:add(mc_ipaddr_f, buffer(offset, 4))
            offset = offset + 4
        elseif cmd == 0xA2 then
            pdu:add(mc_netmask_f, buffer(offset, 4))
            offset = offset + 4
        elseif cmd == 0xA3 then
            pdu:add(mc_defaultgateway_f, buffer(offset, 4))
            offset = offset + 4
        elseif cmd == 0xA4 then
            pdu:add(mc_unknown_f, buffer(offset, 1))
            offset = offset + 1
        elseif cmd == 0xA5 then
            pdu:add(mc_autoreportaddr_f, buffer(offset, 40))
            offset = offset + 40
            pdu:add_le(mc_autoreportport_f, buffer(offset, 2))
            offset = offset + 2
            pdu:add_le(mc_autoreporttimeout_f, buffer(offset, 2))
            offset = offset + 2
        elseif cmd == 0xA6 then
            pdu:add_le(mc_unknown_f, buffer(offset, 8))
            offset = offset + 8
            
            pdu:add(mc_ipaddr_f, buffer(offset, 4))
            offset = offset + 4
            
            pdu:add(mc_netmask_f, buffer(offset, 4))
            offset = offset + 4
            
            pdu:add(mc_defaultgateway_f, buffer(offset, 4))
            offset = offset + 4
            
        elseif cmd == 0xA7 then
            pdu:add(mc_dns_f, buffer(offset, 4))
            offset = offset + 4
            pdu:add(mc_dns_f, buffer(offset, 4))
            offset = offset + 4
        elseif cmd == 0xA8 then
            pdu:add_le(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
            pdu:add(mc_snmpcommunity_f, buffer(offset, 40))
            offset = offset + 40
            pdu:add(mc_snmpcontact_f, buffer(offset, 40))
            offset = offset + 40
            pdu:add(mc_snmplocation_f, buffer(offset, 40))
            offset = offset + 40
            pdu:add(mc_snmptrapserver_f, buffer(offset, 40))
            offset = offset + 40
        elseif cmd == 0xA9 then
            pdu:add_le(mc_mailserver_f, buffer(offset, 44))
            offset = offset + 44
            pdu:add_le(mc_mailsender_f, buffer(offset, 64))
            offset = offset + 64
            pdu:add_le(mc_mailaddress_f, buffer(offset, 64)) -- Email 1..4 follow
            offset = offset + 64
            pdu:add_le(mc_mailaddress_f, buffer(offset, 64))
            offset = offset + 64
            pdu:add_le(mc_mailaddress_f, buffer(offset, 64))
            offset = offset + 64
            pdu:add_le(mc_mailaddress_f, buffer(offset, 64))
            offset = offset + 64
        elseif cmd == 0xAA then
            -- Nothing follows
        elseif cmd == 0xAB then
            pdu:add_le(mc_macaddr_f, buffer(offset, 6)) -- Again!
            offset = offset + 6
        elseif cmd == 0xAC then
            -- Nothing follows
        elseif cmd == 0xAD then
            -- Nothing follows
        elseif cmd == 0xAE then
            -- Nothing follows
        elseif cmd == 0xAF then
            -- Nothing follows
        elseif cmd == 0xB0 then
            -- Nothing follows
        elseif cmd == 0xB1 then
            pdu:add_le(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
            pdu:add_le(mc_bitrate_f, buffer(offset, 4))
            offset = offset + 4
            pdu:add_le(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
        elseif cmd == 0xB2 then
            pdu:add(mc_unknown_f, buffer(offset, 5))
            offset = offset + 5
        elseif cmd == 0xB3 then
            -- Nothing follows
        elseif cmd == 0xB4 then
            pdu:add(mc_unknown_f, buffer(offset, 5))
            offset = offset + 5
        elseif cmd == 0xB6 then
            pdu:add(mc_unknown_f, buffer(offset, 20))
            offset = offset + 20
        elseif cmd == 0xB7 then
            pdu:add(mc_unknown_f, buffer(offset, 20))
            offset = offset + 20
        elseif cmd >= 0xB8 and cmd <= 0xBF then
            -- Nothing follows
        elseif cmd == 0xC1 then
            pdu:add(mc_unknown_f, buffer(offset, 5))
            offset = offset + 5
        elseif cmd == 0xC2 then
            pdu:add(mc_unknown_f, buffer(offset, 12))
            offset = offset + 12
        elseif cmd == 0xC3 then
            -- Nothing follows
        elseif cmd == 0xC4 then
            pdu:add(mc_unknown_f, buffer(offset, 8))
            offset = offset + 8
        elseif cmd == 0xC5 then
            pdu:add(mc_unknown_f, buffer(offset, 8))
            offset = offset + 8
        elseif cmd == 0xC6 then
            pdu:add(mc_unknown_f, buffer(offset, 5))
            offset = offset + 5
        elseif cmd == 0xC7 then
            pdu:add(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
            pdu:add_le(mc_controlport_f, buffer(offset, 2))
            offset = offset + 2
            pdu:add_le(mc_dataport_f, buffer(offset, 2))
            offset = offset + 2
            pdu:add(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
        elseif cmd == 0xC9 then
            pdu:add_le(mc_unknown_f, buffer(offset, 56))
            offset = offset + 56
        elseif cmd == 0xCC then
            pdu:add(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
            pdu:add_le(mc_dataport_f, buffer(offset, 2))
            offset = offset + 2
            pdu:add(mc_unknown_f, buffer(offset, 6))
            offset = offset + 6
        elseif cmd == 0xCD then
            pdu:add(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
            pdu:add(mc_unknown_f, buffer(offset, 1))
            offset = offset + 1
            pdu:add(mc_delimiter1_f, buffer(offset, 1))
            offset = offset + 1
            pdu:add(mc_delimiter2_f, buffer(offset, 1))
            offset = offset + 1
            pdu:add_le(mc_forcetransmit_f, buffer(offset, 2))
            offset = offset + 2
            pdu:add(mc_unknown_f, buffer(offset, 7))
            offset = offset + 7
        elseif cmd == 0xCE then
            pdu:add(mc_unknown_f, buffer(offset, 12))
            offset = offset + 12
        elseif cmd == 0xCF then
            pdu:add_le(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
            pdu:add_le(mc_controlport_f, buffer(offset, 2))
            offset = offset + 2
            pdu:add_le(mc_dataport_f, buffer(offset, 2))
            offset = offset + 2
            pdu:add_le(mc_unknown_f, buffer(offset, 8))
            offset = offset + 8
        elseif cmd == 0xD0 then
            -- Nothing follows
        elseif cmd == 0xD1 then
            pdu:add_le(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4
            for i = 1, 16 do
                 local enabled = buffer(offset, 4):le_uint()

                 local entry = pdu:add(buffer(offset, 12), "[" .. i .. "] " .. (enabled == 1 and "Enabled" or "Disabled"))

                 entry:add_le(mc_enabled_f, buffer(offset, 4))
                 offset = offset + 4

                 entry:add(mc_ipaddr_f, buffer(offset, 4))
                 offset = offset + 4

                 entry:add(mc_netmask_f, buffer(offset, 4))
                 offset = offset + 4
            end
        elseif cmd == 0xD2 then
            pdu:add_le(mc_unknown_f, buffer(offset, 2))
            offset = offset + 2

            pdu:add_le(mc_coldstartmail_f, buffer(offset, 2))
            pdu:add_le(mc_warmstartmail_f, buffer(offset, 2))
            pdu:add_le(mc_authfailuremail_f, buffer(offset, 2))
            pdu:add_le(mc_ipaddrchangemail_f, buffer(offset, 2))
            pdu:add_le(mc_pwchangemail_f, buffer(offset, 2))
            offset = offset + 2

            pdu:add_le(mc_coldstarttrap_f, buffer(offset, 2))
            pdu:add_le(mc_warmstarttrap_f, buffer(offset, 2))
            pdu:add_le(mc_authfailuretrap_f, buffer(offset, 2))
            offset = offset + 2

            pdu:add_le(mc_unknown_f, buffer(offset, 2))
            offset = offset + 2
        elseif cmd == 0xD6 then
            pdu:add_le(mc_unknown_f, buffer(offset, 8))
            offset = offset + 8
        elseif cmd >= 0xD2 and cmd <= 0xFF then
            -- Nothing follows

        else -- if cmd == 0x16 then
            pdu:add_le(mc_unknown_f, buffer(offset, 2))
            offset = offset + 2

            -- Follows SW version, like "03.10"
            local minor = buffer(offset, 1):uint()
            local major = buffer(offset + 1, 1):uint()

            pdu:add_le(mc_swversion_f, buffer(offset, 2), major * 256 + minor, string.format("Software Version: %02X.%02X", major, minor))
            offset = offset + 2
            append_pinfo(pinfo, string.format("SW: %02X.%02X", major, minor))

            pdu:add_le(mc_unknown_f, buffer(offset, 4))
            offset = offset + 4

            -- Follows serial number
            pdu:add_le(mc_serialnum_f, buffer(offset, 2))
            offset = offset + 2

            pdu:add_le(mc_unknown_f, buffer(offset, 6))
            offset = offset + 6
        end
    end

end


-----------------------------------------------------------------------------------------------------------------------------------
-- MOXA_CTRL
--
-- This is the protocol used when a COM-port is opened on a PC. It has no serial data,
-- (that is sent on TCP/950 and other ports). This stream only has control commands.

--[[
#define	ASPP_CMD_NOTIFY		0x26
#define	ASPP_CMD_POLLING	0x27
#define	ASPP_CMD_ALIVE		0x28

#define	ASPP_CMD_IOCTL		16
#define	ASPP_CMD_FLOWCTRL	17
#define	ASPP_CMD_LSTATUS	19
#define	ASPP_CMD_LINECTRL	18
#define	ASPP_CMD_FLUSH		20
#define	ASPP_CMD_OQUEUE		22
#define	ASPP_CMD_SETBAUD	23
#define	ASPP_CMD_START_BREAK	33
#define	ASPP_CMD_STOP_BREAK	34
#define	ASPP_CMD_START_NOTIFY	36
#define	ASPP_CMD_STOP_NOTIFY	37
#define	ASPP_CMD_HOST		43
#define	ASPP_CMD_PORT_INIT	44
#define	ASPP_CMD_WAIT_OQUEUE 	47

#define	ASPP_CMD_IQUEUE		21
#define	ASPP_CMD_XONXOFF	24
#define	ASPP_CMD_PORT_RESET	32
#define	ASPP_CMD_RESENT_TIME	46
#define	ASPP_CMD_TX_FIFO	48
#define ASPP_CMD_SETXON     51
#define ASPP_CMD_SETXOFF    52
]]--

local ctrl_cmds_map = {
    [0x10] = "IOCTL",
    [0x11] = "Flow Control",
    [0x12] = "Line Control",
    [0x13] = "Line Status",
    [0x14] = "Flush",
    [0x16] = "OQueue",
    [0x17] = "Set Baud",
    [0x21] = "Start BREAK",
    [0x22] = "Stop BREAK",
    [0x39] = "Open",
    [0x2C] = "Port Init",
 }
 
local mctrl_cmd_f         = ProtoField.new("Command",      "mctrl.cmd",              ftypes.UINT8,  ctrl_cmds_map, base.HEX)
local mctrl_len_f         = ProtoField.new("Length",       "mctrl.len",              ftypes.UINT8,  nil, base.DEC)
local mctrl_unknown_f     = ProtoField.new("Unknown",      "mctrl.unknown",          ftypes.BYTES,  nil, base.DOT)

 moxa_ctrl.fields = {
    mctrl_cmd_f,
    mctrl_len_f,
    mctrl_unknown_f,
}
 
function heur_dissect_moxa_ctrl(buffer, pinfo, tree)
    if buffer:len() > 20 then return false end

    pinfo.conversation = moxa_ctrl
    moxa_ctrl.dissector(buffer, pinfo, tree)

    return true
end

function moxa_ctrl.dissector(buffer, pinfo, tree)
    if buffer:len() > 20 then return false end

    pinfo.cols.protocol = "MOXA_CTRL"
    pinfo.cols.info = ""
    local pdu = tree:add(moxa_ctrl, buffer)
    
    local is_request = false
    if pinfo.dst_port >= 966 and pinfo.dst_port <= 981 then
       append_pinfo(pinfo, "[C->S]")
       is_request = true
    else
       append_pinfo(pinfo, "[S->C]")
    end

    local offset = 0
    local cmd = buffer(offset, 1):uint()
    pdu:add(mctrl_cmd_f, buffer(offset, 1))
    offset = offset + 1

    if is_request == true then
        pdu:add(mctrl_len_f,  buffer(offset, 1))
        offset = offset + 1

        if offset ~= buffer:len() then
            pdu:add(mctrl_unknown_f, buffer(offset))
        end
    else
        -- In contrast to request, there is not always length field in the PDU.
        -- Many responses just contain the characters "OK". If not, some of the
        -- others may have a length field, but not always...
        local ok = buffer(offset, 2):string()
        if ok == "OK" then
            append_pinfo(pinfo, "OK")
        else
            -- Some commands have a length field
            if cmd == 0x13 or cmd == 0x2F then
                pdu:add(mctrl_len_f,  buffer(offset, 1))
                offset = offset + 1
            end

            pdu:add(mctrl_unknown_f, buffer(offset))
        end

    end
end

-----------------------------------------------------------------------------------------------------------------------------------
local udp_table = DissectorTable.get("udp.port")
local tcp_table = DissectorTable.get("tcp.port")

udp_table:add(0, moxa_conf)
tcp_table:add(966, moxa_ctrl) -- 1st serial port
tcp_table:add(967, moxa_ctrl) -- 2nd serial port
tcp_table:add(968, moxa_ctrl) -- 3rd serial port
tcp_table:add(969, moxa_ctrl) -- 4th serial port
tcp_table:add(970, moxa_ctrl) -- 5th serial port
tcp_table:add(971, moxa_ctrl) -- 6th serial port
tcp_table:add(972, moxa_ctrl) -- 7th serial port
tcp_table:add(973, moxa_ctrl) -- 8th serial port
tcp_table:add(974, moxa_ctrl) -- 9th serial port
tcp_table:add(975, moxa_ctrl) -- 10th serial port
tcp_table:add(976, moxa_ctrl) -- 11th serial port
tcp_table:add(977, moxa_ctrl) -- 12th serial port
tcp_table:add(978, moxa_ctrl) -- 13th serial port
tcp_table:add(979, moxa_ctrl) -- 14th serial port
tcp_table:add(980, moxa_ctrl) -- 15th serial port
tcp_table:add(981, moxa_ctrl) -- 16th serial port

moxa_conf:register_heuristic("udp", heur_dissect_moxa_conf)
moxa_ctrl:register_heuristic("tcp", heur_dissect_moxa_ctrl)
