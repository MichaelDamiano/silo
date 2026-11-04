# Tor with an onion service that forwards to the Silo server. Tor keeps the onion
# keys private (mode 700); only the public hostname is copied to /shared, where
# the server reads it and publishes it to clients.
FROM alpine:3.22
RUN apk add --no-cache tor
COPY torrc /etc/tor/torrc
COPY entrypoint.sh /entrypoint.sh
RUN mkdir -p /var/lib/tor/silo /shared && chown -R tor /var/lib/tor /shared && chmod 700 /var/lib/tor /var/lib/tor/silo && chmod 755 /entrypoint.sh
USER tor
ENTRYPOINT ["/entrypoint.sh"]
