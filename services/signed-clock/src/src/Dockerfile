FROM ubuntu:22.04

RUN apt-get update && apt-get install socat libgmp3-dev libsqlite3-dev -y
RUN mkdir -p data

#RUN mkdir -p data/data
#RUN touch data/data/.log


WORKDIR /data

COPY signed-clock /data

RUN chmod 777 signed-clock

EXPOSE 8082

CMD socat TCP-LISTEN:8082,reuseaddr,fork EXEC:./signed-clock,pty,stderr,setsid,sigint,sane,raw,echo=0

