#!/bin/sh
# Installs the integration on the Wazuh manager. Run as root from this folder.
set -eu
DEST=/var/ossec/integrations
install -m 750 -o root -g wazuh custom-netops-soar "$DEST/custom-netops-soar"
install -m 750 -o root -g wazuh custom-netops-soar.py "$DEST/custom-netops-soar.py"
mkdir -p "$DEST/netops-common"
cp -r ../common/netops "$DEST/netops-common/"
chown -R root:wazuh "$DEST/netops-common"
mkdir -p /var/lib/netops && chown wazuh:wazuh /var/lib/netops
echo "Installed. Now add the <integration> block from ossec-integration.xml to /var/ossec/etc/ossec.conf"
echo "and the rules from local_rules.xml, then: systemctl restart wazuh-manager"
