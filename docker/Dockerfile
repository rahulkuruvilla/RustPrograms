FROM ubuntu:latest

RUN mkdir -p /scripts
COPY rand-beacon /scripts
WORKDIR /scripts
RUN ls
RUN chmod +x rand-beacon

EXPOSE 55090
EXPOSE 5353/udp

ENV P2P_PORT 55090
ENTRYPOINT ["./rand-beacon"]