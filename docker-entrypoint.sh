#!/bin/sh
set -eu

# Fly volumes are mounted after the image filesystem and may initially be
# root-owned. Fix only the mount point, then run the service unprivileged.
chown things:things /data
chmod 0700 /data

exec su-exec things:things "$@"
