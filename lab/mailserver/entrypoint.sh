#!/bin/sh
# Configure Postfix + Dovecot with every weakness SecureMailScope should find.
set -eu

HOST=mail.lab.test
CERT=/etc/ssl/lab/cert.pem
KEY=/etc/ssl/lab/key.pem

# --- weakness: self-signed, 1024-bit RSA, SHA-1, CN does not match the host name
mkdir -p /etc/ssl/lab
if [ ! -f "$CERT" ]; then
  openssl req -x509 -newkey rsa:1024 -sha1 -nodes -days 30 \
    -subj "/O=Lab/CN=wrong-name.lab.test" -keyout "$KEY" -out "$CERT" 2>/dev/null
fi

# --- lab mailbox user (lab-only test credential)
id labuser >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin labuser
echo "labuser:{PLAIN}lab-password-123" > /etc/dovecot/users

# --- Postfix: TLS optional, AUTH allowed before TLS, TLS 1.0 and weak ciphers allowed
postconf -e "myhostname = $HOST" \
  "mydestination = \$myhostname, localhost, lab.test" \
  "inet_interfaces = all" "inet_protocols = ipv4" \
  "mynetworks = 0.0.0.0/0" \
  "smtpd_banner = \$myhostname ESMTP Postfix (lab)" \
  "smtpd_tls_chain_files = $KEY, $CERT" \
  "smtpd_tls_security_level = may" \
  "smtpd_tls_auth_only = no" \
  "smtpd_tls_protocols = >=TLSv1" "smtpd_tls_mandatory_protocols = >=TLSv1" \
  "smtpd_tls_ciphers = low" "smtpd_tls_mandatory_ciphers = low" \
  "tls_low_cipherlist = ALL:@SECLEVEL=0" "tls_medium_cipherlist = ALL:@SECLEVEL=0" \
  "smtpd_sasl_type = dovecot" "smtpd_sasl_path = private/auth" "smtpd_sasl_auth_enable = yes" \
  "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination" \
  "home_mailbox = Maildir/" "maillog_file = /dev/stdout"

postconf -M "submission/inet=submission inet n - y - - smtpd"
postconf -P "submission/inet/smtpd_sasl_auth_enable=yes"
postconf -M "smtps/inet=smtps inet n - y - - smtpd"
postconf -P "smtps/inet/smtpd_tls_wrappermode=yes" "smtps/inet/smtpd_sasl_auth_enable=yes"

newaliases 2>/dev/null || true
dovecot
exec postfix start-fg
