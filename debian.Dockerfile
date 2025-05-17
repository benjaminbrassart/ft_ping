FROM debian:bookworm

RUN <<-EOF
    apt-get update -y
    apt-get install -y inetutils-ping
EOF
