FROM golang:latest as build

WORKDIR /go/src/go-scrt-events

RUN useradd -m dev

COPY . .
RUN chown -R dev:dev /go/src/go-scrt-events
USER dev

RUN go get -d -v
RUN go build 

RUN chmod +x go-scrt-events
ENTRYPOINT [ "./go-sniff" ]

CMD ["--config", "config.yml", "-v", "debug"]