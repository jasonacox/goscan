FROM golang:alpine
RUN apk update && apk add gcc libc-dev make git libpcap-dev
RUN mkdir /app
ADD ./src/main /app/
WORKDIR /app
COPY go.mod ./
RUN go mod download
RUN go build -a -o scan .
CMD ["/bin/true"]

