FROM ubuntu:18.04 as builder

RUN mkdir /home/src
WORKDIR /home/src

RUN apt update; \
    apt install -y build-essential \
    cmake

COPY . .
WORKDIR /home/src/build
RUN rm -rf *
RUN cmake ..; make
