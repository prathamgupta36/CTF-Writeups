FROM node:25.8.1-alpine3.23@sha256:7a2cb14d0e3495975e678976c20abd1f70a9b4923867b9f468fac07084184964 AS base
WORKDIR /app

COPY --chmod=444 ./challenge.js ./runner.js ./
RUN echo -e '#!/bin/sh\n/usr/local/bin/node ./runner.js' > run
RUN chmod +x ./run

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_ENV_FLAG="tkbctf{*** REDACTED ***}" JAIL_POW=30000 JAIL_TIME=15 JAIL_CONNS=4 JAIL_CONNS_PER_IP=1 JAIL_CPU=100 JAIL_MEM=100M JAIL_PIDS=16
