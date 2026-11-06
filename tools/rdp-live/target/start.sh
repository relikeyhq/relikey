#!/bin/sh
# SPDX-License-Identifier: EUPL-1.2
# the target's password arrives in the environment, never argv
echo "rk:${RK_PASSWORD:?}" | chpasswd
unset RK_PASSWORD
/usr/sbin/xrdp-sesman --nodaemon &
exec /usr/sbin/xrdp --nodaemon
