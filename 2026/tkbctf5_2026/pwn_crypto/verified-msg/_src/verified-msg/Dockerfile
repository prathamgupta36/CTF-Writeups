FROM ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54  AS base
WORKDIR /app

RUN apt-get update --yes && apt-get install --yes libssl3 && rm -rf /var/lib/apt/lists/*

COPY --chmod=555 chall run
COPY --chmod=444 flag.txt /flag.txt
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=300 JAIL_CPU=100 JAIL_MEM=10M
