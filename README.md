# XrayKeyParser

Keys parser for xray core.
Supports shadowsocks(outline) and most of vless keys - tls, reality, tcp, websocket, grpc

#### Key must look like  
```
ss://...........#
or
vless://..........#
```

### Always backup your worked shadowsocks config.json 

This app is extract xray keys from web pages and telegramm channels
To run it type in terminal "path_to_app" "path_to_config_file"
Example for linux
```
/bin/xrkeyparser-nix64 /etc/xrkeyparser/config.json
```
### Parameters explanation
```
"xrconfigfile":"/etc/xray/config.json",
```
Path to xray-core config file
```
"xrpath":"/bin/systemctl",
"xrrestartcommand":[
  "restart",
  "xray.service"
],
```
Block of parameters for restarting xray-core. If xray-core is not running as a service, this section may look like this.
```
"xrpath":"/bin/xray",
    "xrrestartcommand":[
        "run",
        "-c",
        "/etc/xray/config.json"
    ],
```

If xray-core is running as a service, this section may look like this.
```
"xrpath":"/bin/systemctl",
    "xrrestartcommand":[
        "restart",
        "xray.service"
    ],
```

```
"outputfile":"/etc/xrkeyparser/parsingresult.json",
```
Results of parsing is save to this file.

```
"ssconfigsectionpath":[
        "outbounds"
    ],
```
Section path for shadowsocks outbound connections in xray config file, where servers will be added.

```
"ssserverseditpos":1,
```
Position from which shadowsocks outbound connections will be edited.

```
"sstag":"outss"
```
Tag for shadowsocks outbounds connection

```
"vlessconfigsectionpath":[
        "outbounds"
    ],
"vlessserverseditpos":1,
"vlesstag":"outvless"
```
Same parametrs for vless outbound connections
```
"links":[
        {
            "url":"https://t.me/some_channel_with_keys",
            "mask":[
                "ss://"
            ],
            "configcount":3,
            "parsetoptobot":false 
        },
        {
            "url":"https://www.some_site_with_keys.com/",
            "mask":[
                "ss://"
            ],
            "configcount":1,
            "parsetoptobot":true 
        }
    ]
```
Links for parsing. In this section 
```
  "configcount" 
```
how many configs do you want to extract from this page
```
  "parsetoptobot"
```
if true parsing will done from top to bottom. 
- Use "true" for pages where new information placing at the top, like sites
- Use "false" for pages where new information placing at the 
