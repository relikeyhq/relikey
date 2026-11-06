#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Lab: answers any TCP connection on port 9000 with this node's name (the stand-in for the edge's services)."""
import os
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9000)); s.listen(64)
while True:
    c, _ = s.accept()
    c.sendall(os.environ["ME"].encode()); c.close()
