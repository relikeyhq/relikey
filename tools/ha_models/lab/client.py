#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Lab client: connects to the site address every 100 ms (200 ms timeout) and logs which node answered."""
import os
import socket
import time
VIP = os.environ["VIP"]
while True:
    t = time.time()
    try:
        c = socket.create_connection((VIP, 9000), timeout=0.2)
        who = c.recv(8).decode() or "-"
        c.close()
    except Exception:
        who = "-"
    print(f"{t:.3f} {who}", flush=True)
    time.sleep(max(0, 0.1 - (time.time() - t)))
