FROM debian:latest

MAINTAINER Josh Bressers "josh@bress.net"

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev git

COPY ./requirements.txt /requirements.txt

WORKDIR /

RUN pip3 install -r requirements.txt

COPY ./bot.py /
COPY ./DWF /DWF
COPY ./helpers/gitconfig /root/.gitconfig
COPY ./helpers/git-askpass-helper.sh /git-askpass-helper.sh

ENTRYPOINT [ "/bot.py" ]
