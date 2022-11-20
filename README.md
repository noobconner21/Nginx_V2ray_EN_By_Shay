###V2Ray Nginx English version

## V2Ray Nginx-based vmess+ws+tls one-click installation script
> Thanks to JetBrains for the non-commercial open source software development license
> Thanks for non-commercial open source development authorization by JetBrains ### About VMess MD5 Authentication Information Elimination Mechanism
> From January 1, 2022, compatibility with MD5 authentication information will be disabled by default on the server side. Any client using MD5 authentication information will not be able to connect to the server with VMess MD5 authentication information disabled. Affected users, we strongly recommend that you reinstall and set alterid to 0 (the default value has been changed to 0), and no longer use the VMess MD5 authentication mechanism If you don't want to reinstall, you can use https://github.com/KukiSa/VMess-fAEAD-disable to force the compatibility of MD5 authentication mechanism

### Telegram Groups
 * Telegram channel : https://t.me/shaystudiolab

### Preparation
 * Prepare a domain name and add the A record.
 * [V2ray Official Description](https://www.v2ray.com/), learn about TLS WebSocket and V2ray related information
 * Install wget

### Installation/update method (h2 and ws versions have been merged)
 Vmess+websocket+TLS+Nginx+Website
 ```
 wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/noobconner21/Nginx-V2Ray-By-Shay/master/install.sh" && chmod +x install.sh && bash install.sh
 ```

VLESS+websocket+TLS+Nginx+Website
```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/noobconner21/Nginx-V2Ray-By-Shay/dev/install.sh" && chmod +x install.sh && bash install.sh
```

### Precautions
 * If you don't understand the specific meaning of each setting in the script, except the domain name, please use the default value provided by the script
 * To use this script, you need to have Linux foundation and experience, understand some knowledge of computer networks, and basic computer operations
 * Currently supports Debian 9+ / Ubuntu 18.04+ / Centos7+, some Centos templates may have compilation problems that are difficult to deal with, it is recommended to change to other system templates when encountering compilation problems
 * The group owner only provides extremely limited support, if you have any questions, you can ask the group members
 * Every Sunday at 3:00 am, Nginx will automatically restart to cooperate with the scheduled task of issuing certificates. During this period, the node cannot connect normally, and the estimated duration is several seconds to two minutes

### Changelog
 > Please check CHANGELOG.md for updated content

 ### Thanks
 * ~~Another branch version of this script (Use Host) address: https://github.com/dylanbai8/V2Ray_ws-tls_Website_onekey Please choose according to your needs~~ The author may have stopped maintenance
 * MTProxy-go TLS version project reference in this script https://github.com/whunt1/onekeymakemtg Thanks whunt1
 * In this script, the original project of the sharp speed 4 in 1 script is referenced https://www.94ish.me/1635.html Thanks for this
 * In this script, the project reference of the modified version of the sharp speed 4 in 1 script https://github.com/ylx2016/Linux-NetSpeed ​​Thanks to ylx2016

### Certificate
 > If you already have the certificate file of the domain name you are using, you can name the crt and key file as v2ray.crt v2ray.key and put it in the /data directory (if the directory does not exist, please create the directory first), please pay attention to the certificate file permissions  and the validity period of the certificate. After the validity period of the custom certificate expires, please renew it by yourself

The script supports automatic generation of let's encrypted certificates, which are valid for 3 months. In theory, the automatically generated certificates support automatic renewal

 ### View client configuration
 `cat ~/v2ray_info.txt`

 ### Introduction to V2ray

 * V2Ray is an excellent open source network proxy tool that can help you experience the Internet smoothly. Currently, it supports Windows, Mac, Android, IOS, Linux and other operating systems on all platforms.
 * This script is a one-click complete configuration script. After all the processes are running normally, you can directly set the client according to the output results and use it
 * Please note: We still strongly recommend that you fully understand the workflow and principles of the entire program

### It is recommended that a single server only build a single agent
 * This script installs the latest version of V2ray core by default
 * The latest version of V2ray core is 4.22.1 (at the same time, please pay attention to the synchronous update of the client core, you need to ensure that the client kernel version >= the server kernel version)
 * It is recommended to use the default port 443 as the connection port
 * The camouflage content can be replaced by yourself.

 ### Precautions
 * It is recommended to use this script in a pure environment. If you are a novice, please do not use the Centos system.
 * Please do not use this program in a production environment until the script actually works.
 * This program relies on Nginx to implement related functions. Please use [LNMP](https://lnmp.org) or other similar Nginx scripts to install Nginx. Users who have installed Nginx should pay special attention. Using this script may cause unpredictable errors (not tested  , if present, a future release may address this issue).
 * Some functions of V2Ray depend on the system time. Please ensure that the UTC time error of the system you use the V2RAY program is within three minutes, regardless of the time zone.
 * This bash depends on [V2ray official installation script](https://install.direct/go.sh) and [acme.sh](https://github.com/Neilpang/acme.sh) to work.
 * For Centos system users, please pre-release program-related ports in the firewall (default: 80, 443)


### Start method

 Start V2ray: `systemctl start v2ray`

 Stop V2ray: `systemctl stop v2ray`

 Start Nginx: `systemctl start nginx`

 Stop Nginx: `systemctl stop nginx`

 ### Related Directories

 Web directory: `/home/wwwroot/3DCEList`

 V2ray server configuration: `/etc/v2ray/config.json`

 V2ray client configuration: `~/v2ray_info.inf`

 Nginx directory: `/etc/nginx`

 Certificate files: `/data/v2ray.key and /data/v2ray.crt` Please pay attention to the certificate authority settings

 ### Donate

 You can use my Bricklayer AFF to buy VPS

 https://bandwagonhost.com/aff.php?aff=63939

 You can use my justmysocks AFF to buy proxies from movers

 https://justmysocks.net/members/aff.php?aff=17621
 
 
● V2ray Core English Version (Translate)
 
 
## Orginal Repo = Wulabing

Translate By SSLaB LK



