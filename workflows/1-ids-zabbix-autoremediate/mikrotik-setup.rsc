# One-time MikroTik setup for workflow 1. Paste into a terminal (RouterOS 7).
# Read every line first and change the names, IPs and password to match your network.
# The drop rule is added by 'netops-ids setup' itself, so it is not here.

# 0. Up to date first.
/system package update install

# 1. A certificate for the REST API (HTTPS).
/certificate add name=rest common-name=router key-usage=tls-server
/certificate sign rest

# 2. A user group with only the rights the scripts need, and a user for them.
/user group add name=netops policy=read,write,api,rest-api,!ftp,!reboot,!policy,!password,!sensitive,!sniff,!romon,!ssh,!telnet,!winbox,!local
/user add name=netops group=netops password=CHANGE-ME address=192.168.88.0/24 comment="netops automation, only from the LAN"

# 3. REST API over HTTPS only, from the LAN only.
/ip service set www-ssl disabled=no certificate=rest address=192.168.88.0/24
/ip service set www disabled=yes

# 4. Copy traffic to the IDS port (switch chip on a hEX / CRS).
#    Start with the LAN port your PC or main switch is on: easier to see than WAN.
#    ether2 = mirrored port, ether5 = cable to the IDS machine's monitor port.
/interface ethernet switch set switch1 mirror-source=ether2 mirror-target=ether5

# Test from your laptop:
#   curl -k -u netops:CHANGE-ME https://192.168.88.1/rest/system/resource
#
# PoE restarts need a port that gives PoE out (hEX PoE, a PoE switch).
# The plain hEX (RB750Gr3) only takes PoE in.
