#!/bin/sh
set -e
tor -f /etc/tor/torrc &
pid=$!
# Wait for Tor to create the onion address, then share just the hostname.
while [ ! -s /var/lib/tor/silo/hostname ]; do sleep 1; done
cp /var/lib/tor/silo/hostname /shared/hostname
echo "Silo onion address: http://$(cat /shared/hostname)"
wait $pid
