# XrayKeyParser

Keys parser for xray core.
Supports shadowsocks(outline), vmess, trojan and vless keys wiht tls, reality, tcp, websocket, grpc stream types

### since version 1.1 names of some parameters in config.json have been changed

#### Key must look like  
```
ss://...........# (ss://........? outline format)
or
vless://..........#
or
vmess://........
or
trojan://.......#
```

### Always backup your worked xray config.json 

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
"configsectionpath":[
        "outbounds"
    ],
```
Section path for outbound connections in xray config file, where servers will be added.

```
"serverseditpos":1,
```
Position from which outbound connections will be edited.

```
"tag":"outss"
```
Tag for outbounds connection

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

The following block of parameters is used to filter ip addresses by country. Because some genius makes servers(for example shadowsocks) in country with powerfull censorship, like Russia. You can exclude this ip from use if it belongs to a specific country.

```
"ipcheckserver"
```
Url to check if parsed IP address belongs to a country you don't want to connect to.

```
"ipcheckkey"
```
Key in json response
```
"ipcheckvalue"
```
Value in json response

It may look like
```
 "ipcheckserver":"https://ipinfo.io/",
 "ipcheckkey":"country",
 "ipcheckvalue":"RU"
```
or
```
 "ipcheckserver":"api.2ip.io/",
 "ipcheckkey":"country",
 "ipcheckvalue":"Russian Federation"
```
I found two servers wich can get simple request and send json response. To check it i used curl
```
curl https://ipinfo.io/1.2.3.4
```
or
```
curl api.2ip.io/1.2.3.4
```
In output you can see how it returns country. For example
```
curl api.2ip.io/1.2.3.4
{
    "ip": "1.2.3.4",
    "city": "Moscow",
    "region": "Moscow",
    "country": "Russian Federation",
    "code": "RU",
    "emoji": ""
    "lat": "",
    "lon": "",
    "timezone": "Europe/Moscow",
    "asn": {
        "id": "",
        "name": "",
        "hosting": false
    },
    "signup": "Get more at 2ip.io/free"
}
```
If you know another servers like those two let me know
