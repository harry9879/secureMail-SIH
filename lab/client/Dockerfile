FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      swaks openssl curl tcpdump ca-certificates netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
