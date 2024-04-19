FROM debian:bullseye-slim AS build

RUN \
	apt-get update -y && \
	apt-get install -y build-essential

WORKDIR /src

COPY ping .

RUN make -j CFLAGS='-g3'



FROM debian:bullseye-slim

RUN \
	apt-get update -y && \
	apt-get install -y inetutils-ping

COPY --from=build /src/ft_ping /usr/bin/ft_ping
