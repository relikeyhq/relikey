#!/bin/bash
# SPDX-License-Identifier: EUPL-1.2
# ReliKey 0028 evidence E1: the address arbiter on an emulated site network (rootless podman bridge on the hub).
# Containers relikey-arb-* on network relikey-arb only; all removed at the end. Writes ~/arblab/results/*.
set -u
B=$(pwd); L=$HOME/arblab; rm -rf "$L"; mkdir -p "$L/results"; cp "$B"/*.py "$L/"; cd "$L"
NET=relikey-arb; SUB=10.77.0; VIP=$SUB.100; IMG=localhost/relikey-arb-lab
cleanup(){ podman rm -f relikey-arb-a relikey-arb-b relikey-arb-w relikey-arb-c >/dev/null 2>&1; }
trap 'cleanup; podman network rm -f $NET >/dev/null 2>&1' EXIT
cat > Containerfile <<'EOF'
FROM docker.io/library/python:3.12-alpine
RUN apk add --no-cache iproute2 iputils-arping
EOF
podman build -q -t $IMG . >/dev/null || { echo "build failed"; exit 1; }
podman network rm -f $NET >/dev/null 2>&1; podman network create --subnet $SUB.0/24 $NET >/dev/null
CAP="--cap-add NET_ADMIN --cap-add NET_RAW"

start(){ # $1 mode (normal|static|vmac)
  cleanup
  local v=0; [ "$1" = vmac ] && v=1
  podman run -d --name relikey-arb-w --network $NET --ip $SUB.10 -e MY_IP=$SUB.10 -v "$L:/l:ro" $IMG python3 /l/witness.py >/dev/null
  for n in A B; do
    lc=$(echo $n | tr A-Z a-z); ip=$SUB.2$([ $n = A ] && echo 1 || echo 2); pip=$SUB.2$([ $n = A ] && echo 2 || echo 1)
    podman run -d --name relikey-arb-$lc --network $NET --ip $ip $CAP -v "$L:/l:ro" \
      -e ME=$n -e MY_IP=$ip -e PEER=$([ $n = A ] && echo B || echo A) -e PEER_IP=$pip -e WITNESS=$SUB.10 -e VIP=$VIP -e VMAC=$v \
      -e START_HOLD=$([ $n = A ] && echo 1 || echo 0) $IMG sh -c "python3 /l/serve.py & exec python3 -u /l/arb.py" >/dev/null
  done
  sleep 3
  podman run -d --name relikey-arb-c --network $NET --ip $SUB.30 $CAP -v "$L:/l:ro" -e VIP=$VIP $IMG sh -c "sleep 2; exec python3 -u /l/client.py" >/dev/null
  sleep 4
  if [ "$1" = static ]; then   # a client that never learns a new MAC for the address (ignores gratuitous ARP)
    mac=$(podman exec relikey-arb-c ip neigh show $VIP | awk '{print $5}')
    podman exec relikey-arb-c ip neigh replace $VIP lladdr $mac nud permanent dev eth0
  fi
}
finish(){ # $1 name
  sleep 25
  podman logs relikey-arb-c > results/$1.client 2>&1
  podman logs relikey-arb-a > results/$1.a 2>&1; podman logs relikey-arb-b > results/$1.b 2>&1
  echo "done $1" >> results/progress
}
for mode in normal static vmac; do
  # 1. the holder dies; it returns 30 s later and must not take the address back
  start $mode; echo "$(date +%s.%N) EVENT kill A" > results/crash-$mode.events
  podman kill relikey-arb-a >/dev/null; sleep 30; echo "$(date +%s.%N) EVENT A back" >> results/crash-$mode.events
  podman start relikey-arb-a >/dev/null; finish crash-$mode
  # 2. the holder freezes for 30 s (cgroup freezer), then wakes
  start $mode; echo "$(date +%s.%N) EVENT freeze A" > results/freeze-$mode.events
  podman pause relikey-arb-a >/dev/null; sleep 30; echo "$(date +%s.%N) EVENT thaw A" >> results/freeze-$mode.events
  podman unpause relikey-arb-a >/dev/null; finish freeze-$mode
  # 3. the nodes stop hearing each other; the witness decides; then they hear each other again
  start $mode; echo "$(date +%s.%N) EVENT cut A-B" > results/cut-$mode.events
  podman exec relikey-arb-a touch /tmp/cut-peer; podman exec relikey-arb-b touch /tmp/cut-peer; sleep 30
  echo "$(date +%s.%N) EVENT heal A-B" >> results/cut-$mode.events
  podman exec relikey-arb-a rm -f /tmp/cut-peer; podman exec relikey-arb-b rm -f /tmp/cut-peer; finish cut-$mode
  # 4. the witness is down, then the holder dies: the survivor has no majority (no holder expected)
  start $mode; echo "$(date +%s.%N) EVENT witness down" > results/nowit-$mode.events
  podman stop -t 1 relikey-arb-w >/dev/null; sleep 5; echo "$(date +%s.%N) EVENT kill A" >> results/nowit-$mode.events
  podman kill relikey-arb-a >/dev/null; finish nowit-$mode
done
echo ALLDONE >> results/progress
