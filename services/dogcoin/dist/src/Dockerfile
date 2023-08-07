FROM ubuntu:22.04

RUN apt-get update && apt-get install socat -y

RUN mkdir -p data

RUN mkdir -p data/data
RUN touch data/data/.log


WORKDIR /data

COPY coined /data

RUN chmod 777 coined

EXPOSE 8082

CMD socat TCP-LISTEN:8082,reuseaddr,fork EXEC:./coined,pty,stderr,setsid,sigint,sane,raw,echo=0
