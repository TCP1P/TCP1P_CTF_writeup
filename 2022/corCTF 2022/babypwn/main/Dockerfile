# FROM pwn.red/jail:0.3.0
# COPY --from=ubuntu:20.04 / /srv
# COPY babypwn /srv/app/run
# COPY flag.txt /srv/app

FROM ubuntu:20.04
RUN apt-get update && apt-get install -y gdb
RUN apt-get install -y python3
COPY babypwn /app/run
COPY flag.txt /app