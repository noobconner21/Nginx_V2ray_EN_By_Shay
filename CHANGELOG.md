## 2020-06-11
 * Switch from v2ray to v2fly
 * mtproxy installation offline

 ## 2020-6-5
 * Add ws tls Quantmumult import
 * Add multithreaded compilation
 * Fix the problem of adding cron repeatedly
 ## 2020-6-3
 * Add Nginx ipv6 listener TLS1.3 0 RTT (merge)
 * Adapt to Nginx ipv6 listening port modification
 * Changed Nginx version 1.16.1 to 1.18.0
 * Changed ws path length from fixed 8 bits to range random length

 ## 2020-2-16
 1.1.0
 * Fixed the problem that the certificate was not applied correctly after updating
 * Added old configuration file retention
 * Add installation process TLS version selection
 * Change v2ray_qr_config_file location
 * Fix v2ray daemon judgment logic error
 * Add Nginx conflict detection

 ## 2020-2-7
 1.0.7
 * Fix automatic certificate renewal Nginx restart exception
 * Fix bbr4 in 1 403 forbidden issue
 * Fix the problem of abnormal cleaning of some temporary files
 * Changed to keep only TLS1.3 by default
 * Added uninstall to provide Nginx keep option
 * Added Nginx configuration file XFF thanks to tg:@Cliwired
 * Added ws DOH configuration thanks to tg:@auth_chain_b

 ## 2020-01-25
 * Fix curl dependency missing
 * Add MT-proxy-go installation code, thanks to whunt1 for his contribution
 * Fix the problem of skipping certificate issuance caused by successful test issuance, formal issuance failure, and subsequent reinstallation

## 2019-12-30
 > This update has a lot of content, and some codes have been refactored and merged. Please note that when using the new version of the management script, it is recommended that users first uninstall and then reinstall the corresponding version
 * Added an interactive menu, refactored into an installation management script, the version number is initialized to 1.0, and many functions are merged
 * Merge the h2 version into the main version and follow the update, the h2 version (old version) stops maintenance
 * Added option to change UUID ALTERID PORT TLS version
 * Added V2ray log record and view
 * Added the introduction of 4 in 1 bbr sharp speed script, thanks to 94ish.me
 * Added uninstall option
 * Added manual update of the certificate, the principle is the same as that of the scheduled task update, the validity period of the certificate is only less than 30 days, and the mandatory update is not enabled by default

 ## 2019-11-28
 * Added dependency on rng-tools haveged to increase replenishment rate of system entropy pool
 * Double 叒叕...Fix the problem that Nginx cannot start automatically after restarting
 
 ## 2019-11-27
 * Adjust certificate issuance detection from 0:00 am on Sunday to 3:00 am on Sunday
 * Added parameter boost can directly use the four-in-one bbr/sharp script
 * The adjustment parameter tls_modify is compatible with TLS1.1 and can be selected on demand
 
 ## 2019-11-26
 > This version may solve the ancestral broken metaphysics problem of ws tls, if necessary, please execute the installation script to update
 * The TLS configuration is modified to support 1.2 and 1.3, which can be switched through the tls_modify option
 * Uninstall function support can be uninstalled through the uninstall option
 
 ### 2019-10-17
 > It is recommended that users who encounter problems reset the system and reinstall
 * CHANGED Added Nginx systemd serverfile
 * Fix and try to fix Nginx boot self-starting problem
 
 ### 2019-10-16
 * Adapt to Centos8 Debian10 Ubuntu19.04
 * Fix the problem that scheduled tasks do not take effect under some systems
 * Fix the error that the time synchronization service cannot be installed under Centos8
 * Fix the problem that the certificate will not be automatically renewed under some systems
 * Fix the problem that the Nginx boot self-start configuration fails in some systems
 * Changed When repeated installations, repeated certificate applications for the same domain name will not be performed to prevent the limit on the number of Let's encrypt APIs
 * Change the default alterID 64 -> 4 to reduce resource usage
 * Change the nginx installation method from source to compile and install, and use the new version of Openssl to support tls1.3
 * Change nginx configuration file ssl_protocols ssl_ciphers to adapt to tls1.3
 * Changes Debian8 Ubuntu 16.04 adaptation work canceled (this version may still be available)
 * Change the default page disguised as a html5 game
 * New installation is complete, and the node configuration information is kept on file
 * Added the use of custom certificates
 * Added link import import
 * Added QR code import
 
 ## 2018-04-10
 * vmess+http2 over tls script update
 
 ## 2018-04-08
 v3.3.1 (Beta)
 * Minor adjustments to installation dependencies
 * Readme content adjustment
 
 ## 2018-04-06
 v3.3 (Beta)
 * Fix Nginx startup failure after Ubuntu 16.04/17.10 installation
 * Fixed the problem of repeated addition of Nginx installation sources due to repeated execution of scripts
 * Fixed the problem that Nginx failed to start due to abnormal Nginx configuration files caused by repeated execution of scripts
 * Fix Nginx version issue caused by incorrect addition of Nginx Ubuntu sources
 
 ## 2018-04-03
 V3.2 (Beta)
 * Nginx version updated to mainline version
 * Add TLS1.3 http2 to Nginx configuration
 
 ## 2018-03-26
 V3.1 (Beta)
 * 1. Remove irrelevant dependencies
 * 2. The installation sequence is changed, SSL generation is placed at the end of the program
 * 3. The installed version of NGINX is unified to the latest stable version (to prepare for the possible adaptation of http2 and tls1.3 in the future, the default NGINX version of the debian source is too low to support http2)
 
 ## 2018-03-18
 V3.0(Stable)
 * 1. Fix the Bad Request problem that occurs when accessing a specific disguised Path during Path splitting (unified as 404 Not Found)
 
## 2018-03-10
 V3.0(beta)
 * 1. Code reconstruction for some functions
 * 2. Added 301 redirection, that is, http is forced to jump to https
 * 3. Added page camouflage (a calculator program)
 * 4. The disguised path is changed from the original /ray/ to randomly generated
 
 ## 2018-03-05
 V2.1.1(stable)
 * 1. After the change detects that the port is occupied, try to automatically kill the related process
 * 2. Try to fix the GCE default pure template port 80 occupation problem (waiting for more feedback)
 
 ## 2018-02-04
 V2.1.1(stable)
 * 1. Change the judgment method of local_ip, change from get local network card to command get public network IP.
 * 1. Fix the false positive problem that the domain name dns resolution IP does not match the local IP
 
 ## 2018-01-28
 v2.1.1(stable)
 * 1. Fix the abnormal problem of port occupancy judgment caused by the lack of lsof dependency
 
 ## 2018-01-27
 v2.1.1 (stable)
 * 1. Fix the installation failure problem caused by lack of crontab (scheduled task) dependency on some models
 * 2. Improve port occupancy judgment
 
 ## 2017-12-06
 V2.1 (stable)
 * 1. Fix the problem that Centos7 cannot find the Nginx installation package
 * 2. Improve the reminder logo of SElinux configuration process

 V2.0（stable）
 * 1. Add Centos7 system support
 * 2. Add custom port and custom alterID
 * 3. Improve the dependencies required for installation
 * 4. Fix the installation interruption problem caused by the abnormal judgment of the Ubuntu series system version
 * 5. Fix bugs

 V1.02 (beta)
 * 1. Increase the system judgment, currently only support the newer mainstream development version system with systemd
 * 2. Refactoring of local IP acquisition method

 ## 2017-12-05

 V1.01 (beta)
 * 1. Perfect support Debian9
 * 2. Fix the local ip judgment error caused by Debian9 not installing net-tools by default
 * 3. Fix bc installation problem
 * 4. Add the option to continue the installation when the ip judgment is inconsistent (due to the special situation of some vps, it is judged that the internal network IP or its own network card information, or the public network ip is inconsistent with the information within the service period, etc.)

 V1.0 (beta)
 * 1. Currently only supports Debian 8+ / Ubuntu 16.04+
 * 2. Gradually improving