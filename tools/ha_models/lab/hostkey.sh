#!/bin/bash
# ReliKey 0028 evidence E3: do two Warpgate 0.30.4 instances given one SSH host key file before their first start
# present the same host key? Two podman volumes, unattended setup in each, the same host-ed25519 placed in each
# keys path, both run on loopback ports, ssh-keyscan both. Only relikey-hk-* containers and volumes; removed at the end.
set -u
WG=ghcr.io/warp-tech/warpgate:0.30.4@sha256:c81537790bd316686ba5eb89f674cbfe3b35da16bde35f58d0577bed3372bdda
BB=docker.io/library/busybox:1.37.0
W=$(mktemp -d); trap 'cd /; podman rm -f relikey-hk-a relikey-hk-b >/dev/null 2>&1; podman volume rm -f relikey-hk-a relikey-hk-b >/dev/null 2>&1; rm -rf "$W"' EXIT
ssh-keygen -q -t ed25519 -N "" -C shared-site-key -f "$W/host-ed25519"
echo "shared key: $(ssh-keygen -lf "$W/host-ed25519.pub" | awk '{print $2}')"
i=0
for n in a b; do
  i=$((i+1)); http=$((18900+i)); ssh=$((12300+i))
  podman volume create relikey-hk-$n >/dev/null
  PW=$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')
  podman run --rm -e "WARPGATE_ADMIN_PASSWORD=$PW" -v relikey-hk-$n:/data "$WG" --config /data/warpgate.yaml \
    unattended-setup --data-path /data --http-port $http --ssh-port $ssh >/dev/null 2>&1 || { echo "setup $n failed"; exit 1; }
  podman run --rm -v relikey-hk-$n:/data "$BB" sed -i -e 's/0\.0\.0\.0:/127.0.0.1:/g' -e 's/\[::\]:/127.0.0.1:/g' /data/warpgate.yaml
  # E3 step 3: name the keys path, so Warpgate imports a host-ed25519 file found there at its first start
  podman run --rm -v relikey-hk-$n:/data "$BB" sh -c 'awk "{print} /^ssh:\$/{print \"  keys: /data/keys\"}" /data/warpgate.yaml > /data/w.tmp && mv /data/w.tmp /data/warpgate.yaml && grep -n -A1 "^ssh:" /data/warpgate.yaml'
  echo "== $n after setup: keys path and config"
  podman run --rm -v relikey-hk-$n:/data "$BB" sh -c 'ls -la /data/keys 2>/dev/null; grep -nE "keys|ssh" /data/warpgate.yaml | head -8'
  # the shared key, in the keys path, before the first run
  podman run --rm -v relikey-hk-$n:/data -v "$W:/k:ro" "$BB" sh -c 'mkdir -p /data/keys && cp /k/host-ed25519 /data/keys/host-ed25519 && chmod 600 /data/keys/host-ed25519 && chown -R $(stat -c %u:%g /data/db) /data/keys && ls -la /data/keys'
  podman run -d --name relikey-hk-$n --network host -v relikey-hk-$n:/data "$WG" --config /data/warpgate.yaml run >/dev/null
done
sleep 12
for n in a b; do
  i=$([ $n = a ] && echo 1 || echo 2); ssh=$((12300+i))
  fp=$(ssh-keyscan -T 5 -t ed25519 -p $ssh 127.0.0.1 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
  echo "node $n ssh port $ssh presents: ${fp:-none}"
  podman logs relikey-hk-$n 2>&1 | grep -iE 'host key|import|generat|keys|error|warn' | cut -c1-220 | head -8
done
echo "== restart b, key kept?"
podman restart relikey-hk-b >/dev/null; sleep 10
echo "node b after restart: $(ssh-keyscan -T 5 -t ed25519 -p 12302 127.0.0.1 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')"
podman run --rm -v relikey-hk-b:/data "$BB" ls -la /data/keys
