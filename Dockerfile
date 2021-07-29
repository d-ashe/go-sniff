FROM golang:latest as build

WORKDIR /go/src/go-sniff

RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get install -y lsb-release
RUN wget https://packages.ntop.org/apt/buster/all/apt-ntop.deb \
    && apt install ./apt-ntop.deb
RUN apt-get update \
    && apt-get install -y pfring

COPY . .

RUN go get -d -v
RUN go build 
RUN chmod +x go-sniff
#ENTRYPOINT [ "./go-sniff" ]
#CMD ["--config", "config.yml", "-v", "debug"]
CMD ["/bin/bash"]