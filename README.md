# OWASP CRS - XXE Lua Plugin

## Description

This is a plugin that brings protection against XXE attacks to CRS.

The plugin is replacing ModSecurity build-in XML parser with a custom one, which
allows it to scan for XXE payloads inside `DOCTYPE` element (this element isn't
accessible while using ModSecurity build-in XML parser). The XML parsing alone
is done via bundled Lua script and using a LuaExpat library. Unfortunately, way
of accessing parsed XML data is NOT backward compatible compared to ModSecurity
build-in XML parser, which means that rules (including exclusion ones) using
`XML` collection needs to be adjusted. The plugin already contains all
adjustments needed for core CRS rules.

For XXE protection without Lua requirement, see [XXE plugin](https://github.com/coreruleset/xxe-plugin).

## Prerequisities

 * ModSecurity compiled with Lua support
 * LuaExpat library

## How to determine whether you have Lua support in ModSecurity

Most modern distro packages come with Lua support compiled in. If you are
unsure, or if you get odd error messages (e.g. `EOL found`) chances are you are
unlucky. To be really sure look for ModSecurity announce Lua support when
launching your web server:

```
... ModSecurity for Apache/2.9.5 (http://www.modsecurity.org/) configured.
... ModSecurity: APR compiled version="1.7.0"; loaded version="1.7.0"
... ModSecurity: PCRE compiled version="8.39 "; loaded version="8.39 2016-06-14"
... ModSecurity: LUA compiled version="Lua 5.3"
...
```

If this line is missing, then you are probably stuck without Lua. Check out the
documentation at [coreruleset.org](https://coreruleset.org/docs) to learn how to
get Lua support for your installation.

## LuaExpat library installation

LuaExpat library should be part of your linux distribution. Here is an example
of installation on Debian linux:  
`apt install lua-expat`

## Plugin installation

For full and up to date instructions for the different available plugin
installation methods, refer to [How to Install a Plugin](https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin)
in the official CRS documentation.

## Testing

After configuration, XXE protection should be tested, for example, using:  
`curl http://localhost -H "Content-Type: application/xml" --data '<!--?xml version="1.0" ?--><!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow"> ]><userInfo><firstName>John</firstName><lastName>&ent;</lastName></userInfo>'`

Using default CRS configuration, this request should end with status 403 with
the following message in the log:
`ModSecurity: Warning. Pattern match "<!ENTITY(?:\\\\s+%)?\\\\s+[^\\\\s]+\\\\s+(?:SYSTEM|PUBLIC)(?:\\\\s+['\\"][^'\\"]*['\\"])?\\\\s+['\\"]+(?i:data|expect|file|ftp|glob|gopher|http|https|jar|jdbc|ldap|ogg|phar|php|rar|ssh2|zip|zlib)://" at REQUEST_BODY. [file "/path/plugins/xxe-lua-before.conf"] [line "38"] [id "9598100"] [msg "XML eXternal Entity: Local / Remote File Inclusion attempt"] [data "Matched Data: <!ENTITY ent SYSTEM \\x22file:// found within REQUEST_BODY: <!--?xml version=\\x221.0\\x22 ?--><!DOCTYPE replace [<!ENTITY ent SYSTEM \\x22file:///etc/shadow\\x22> ]><userInfo><firstName>John</firstName><lastName>&ent;</lastName></userInfo>"] [severity "CRITICAL"] [ver"xxe-lua-plugin/1.0.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-lfi"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/152/248/250/228"] [hostname "localhost"] [uri "/"] [unique_id "YvOVh0FqCSuP60rRUUMGwgAAAAg"]`

## License

Copyright (c) 2022-2024 OWASP CRS project. All rights reserved.

The OWASP CRS and its official plugins are distributed
under Apache Software License (ASL) version 2. Please see the enclosed LICENSE
file for full details.
