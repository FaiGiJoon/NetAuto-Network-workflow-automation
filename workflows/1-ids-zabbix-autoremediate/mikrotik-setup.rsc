# One-time MikroTik setup for workflow 1. Paste into a terminal (RouterOS 7).
# Read every line first and change the names and IPs to match your network.

# 1. Drop everything from the blocklist, as early as possible (raw table, before connection tracking).
/ip firewall raw add chain=prerouting src-address-list=netops-blocked action=drop comment="netops: drop blocked sources"

# 2. A user group with only the rights the scripts need, and a user for them.
/user group add name=netops policy=read,write,api,rest-api,!ftp,!reboot,!policy,!password,!sensitive,!sniff,!romon,!ssh,!telnet,!winbox,!local
/user add name=netops group=netops password=CHANGE-ME address=10.255.0.0/24 comment="netops automation, only from the mgmt network"

# 3. REST API over HTTPS only (needs a certificate: /certificate add name=rest common-name=router; sign it).
/ip service set www-ssl disabled=no certificate=rest address=10.255.0.0/24
/ip service set www disabled=yes

# 4. Send a copy of WAN traffic to the IDS box. On a hEX or CRS switch chip:
#    ether1 = WAN uplink, ether5 = the NIC of the Snort/Suricata machine.
/interface ethernet switch set switch1 mirror-source=ether1 mirror-target=ether5
