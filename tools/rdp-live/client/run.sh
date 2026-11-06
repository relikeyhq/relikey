#!/bin/sh
# SPDX-License-Identifier: EUPL-1.2
# holds one RDP session through Warpgate under a virtual display until it is cut; prints how it ended
Xvfb :1 -screen 0 1024x768x16 >/dev/null 2>&1 &
sleep 1
DISPLAY=:1 xfreerdp /v:"${RDP_HOST:?}":"${RDP_PORT:-3389}" /u:"${RDP_USER:?}" /from-stdin:force /cert:ignore /log-level:INFO <<P
${RDP_PASSWORD:?}
P
echo "xfreerdp exited: $?"
