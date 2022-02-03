FROM ubuntu:latest
MAINTAINER xyz@gmail.com 

RUN apt-get upgrade 
RUN apt-get install –y nginx 

WORKDIR /app
COPY . .

CMD [“echo”,”Image created”]