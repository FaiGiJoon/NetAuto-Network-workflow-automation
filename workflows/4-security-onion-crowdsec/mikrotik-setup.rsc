# One-time MikroTik setup for workflow 4 (RouterOS 7). Change names and IPs first.

# Drop everything CrowdSec bans, before connection tracking.
/ip firewall raw add chain=prerouting src-address-list=crowdsec-blocked action=drop comment="crowdsec: drop banned sources"

# Copy WAN traffic to the Security Onion sniffing interface (switch chip on hEX/CRS).
# ether1 = WAN uplink, ether6 = Security Onion's monitor NIC (no IP address on that NIC).
/interface ethernet switch set switch1 mirror-source=ether1 mirror-target=ether6

# REST user for the bouncer: see workflows/1-ids-zabbix-autoremediate/mikrotik-setup.rsc steps 2 and 3.
