FROM golang:1.20-alpine

WORKDIR /app

RUN apk update && apk add --no-cache ca-certificates tzdata

ENV TZ=America/New_York

COPY go.mod ./
COPY go.sum ./

RUN cp /usr/share/zoneinfo/America/New_York /etc/localtime
RUN go mod download

COPY *.go ./

RUN go build -o /seacow-daemon

CMD [ "/seacow-daemon" ]