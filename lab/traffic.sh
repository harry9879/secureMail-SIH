#!/bin/sh
# Generate one of each traffic pattern against the lab and capture it.
# Run inside the client container:  docker compose exec client sh /lab/traffic.sh
set -u
OUT=/captures/lab.pcap
S=mail.lab.test
X=stripped.lab.test
U=labuser
P=lab-password-123      # lab-only test credential (see mailserver/entrypoint.sh)

mkdir -p /captures
tcpdump -i eth0 -s 0 -U -w "$OUT" 'tcp port 25 or tcp port 587 or tcp port 465 or tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995' &
TCPDUMP=$!
sleep 2

run() { echo "== $1"; shift; "$@" >/dev/null 2>&1 || true; sleep 1; }

run "relay with STARTTLS (healthy baseline x3)"  sh -c "for i in 1 2 3; do swaks -s $S:25 -t labuser@lab.test -f a@partner.test --tls; done"
run "submission, AUTH LOGIN in cleartext"        swaks -s $S:587 -t labuser@lab.test -f $U@lab.test -a LOGIN -au $U -ap $P
run "submission via stripping proxy"             swaks -s $X:587 -t labuser@lab.test -f $U@lab.test -a LOGIN -au $U -ap $P --tls-optional
run "relay forced to TLS 1.0"                    sh -c "echo QUIT | openssl s_client -starttls smtp -connect $S:25 -tls1 -cipher 'ALL:@SECLEVEL=0'"
run "SMTPS (implicit TLS)"                       swaks -s $S:465 -t labuser@lab.test -f $U@lab.test --tlsc -a PLAIN -au $U -ap $P
run "IMAP LOGIN in cleartext"                    curl -s "imap://$S/INBOX" -u "$U:$P"
run "IMAP via stripping proxy"                   curl -s "imap://$X/INBOX" -u "$U:$P" --ssl
run "IMAPS"                                      curl -sk "imaps://$S/INBOX" -u "$U:$P"
run "POP3 USER/PASS in cleartext"                curl -s "pop3://$S/" -u "$U:$P"
run "POP3 with STLS"                             curl -sk "pop3://$S/" -u "$U:$P" --ssl-reqd

sleep 2
kill "$TCPDUMP"
wait "$TCPDUMP" 2>/dev/null
echo "capture written to $OUT (lab/captures/lab.pcap on the host)"
