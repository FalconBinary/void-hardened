#!/bin/sh
[ -s /run/vh-totp.pid ] && kill "$(cat /run/vh-totp.pid)" 2>/dev/null
:
