# Postfix + Dovecot, misconfigured ON PURPOSE as a weak-TLS test source.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix dovecot-imapd dovecot-pop3d openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY dovecot-weak.conf /etc/dovecot/conf.d/99-weak.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25 587 465 143 993 110 995
ENTRYPOINT ["/entrypoint.sh"]
