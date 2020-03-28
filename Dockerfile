FROM golang:latest as builder
WORKDIR /go/src/github.com/couchbaselabs/sdk-doctor/
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
COPY ./ ./
RUN go get -t && \
    go test ./ && \
    go build -a -installsuffix cgo -o sdk-doctor-linux .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /sdk-doctor
COPY --from=builder /go/src/github.com/couchbaselabs/sdk-doctor/sdk-doctor-linux .
ENTRYPOINT ["./sdk-doctor-linux"]
