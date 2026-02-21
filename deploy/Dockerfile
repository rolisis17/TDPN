FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY services ./services
RUN go build -o /out/node ./cmd/node

FROM alpine:3.20
RUN adduser -D -h /app nodeuser
WORKDIR /app
COPY --from=builder /out/node /usr/local/bin/node
USER nodeuser
ENTRYPOINT ["/usr/local/bin/node"]

