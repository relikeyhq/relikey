#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Lab: answers a TCP connection to the site's address (VIP) on port 9000 with this node's name (the stand-in for the
edge's services). It binds the site's address only, with IP_FREEBIND, so it listens before the node holds the address
and answers only while it does."""
import os
import socket
IP_FREEBIND = getattr(socket, "IP_FREEBIND", 15)   # Linux: bind an address this node does not hold yet
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_IP, IP_FREEBIND, 1)
s.bind((os.environ["VIP"], 9000)); s.listen(64)
while True:
    c, _ = s.accept()
    c.sendall(os.environ["ME"].encode()); c.close()
