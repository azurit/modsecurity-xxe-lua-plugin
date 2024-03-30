-- -----------------------------------------------------------------------
-- OWASP CRS Plugin
-- Copyright (c) 2022-2024 Core Rule Set project. All rights reserved.
--
-- The OWASP CRS plugins are distributed under
-- Apache Software License (ASL) version 2
-- Please see the enclosed LICENSE file for full details.
-- -----------------------------------------------------------------------

function main(request_body)
        pcall(require, "m")
	local ok, lxp = pcall(require, "lxp")
	if not ok then
		m.log(2, "XXE Lua Plugin ERROR: LuaExpat library not installed, please install it or disable this plugin.")
		return nil
	end

	local xml = ""
	local xmlattr_key = 0
	callbacks = {
		-- attributes parameter, type table, format (differs from what LuaExpat documentation says):
		-- {
		-- [1] = ["attribute1_name"],
		-- [2] = ["attribute2_name"],
		-- ["attribute1_name"] = ["attribute1_value"],
		-- ["attribute2_name"] = ["attribute2_value"],
		-- ...
		-- }
		StartElement = function (parser, name, attributes)
			local cnt = 1
			for _, _ in pairs(attributes) do
				if attributes[cnt] ~= nil then
					m.setvar(string.format("tx.xmlattrs.%s", xmlattr_key), attributes[attributes[cnt]])
					xmlattr_key = xmlattr_key + 1
				else
					break
				end
				cnt = cnt + 1
			end
		end,
		CharacterData = function (parser, value)
			xml = xml .. value
		end
	}
	p = lxp.new(callbacks)
	result, msg, line, col, pos = p:parse(request_body)
	if result then
		p:close()
		m.setvar("tx.xml", xml)
	else
		m.log(2, string.format("XXE Lua Plugin ERROR: XML parser error: XML: Failed parsing document, msg: %s line: %s col: %s pos: %s.", msg, line, col, pos))
	end
	return nil
end
