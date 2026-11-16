#!/usr/bin/env python3
"""Write Oxidized's router.db (name:ip:model:group) from data/devices.yml,
so Oxidized always backs up exactly the devices this repo manages.

    python scripts/oxidized_routerdb.py > /etc/oxidized/router.db
"""

from netlib import load_from_disk

MODELS = {"routeros": "routeros", "ios": "ios"}

for dev in load_from_disk()["devices"]:
    print(f"{dev['name']}:{dev['mgmt_ip']}:{MODELS[dev['platform']]}:{dev['site']}")
