FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY services ./services
RUN go build -o /out/node ./cmd/node

FROM alpine:3.20
RUN apk add --no-cache iproute2 wireguard-tools
RUN adduser -D -h /app nodeuser
WORKDIR /app
COPY --from=builder /out/node /usr/local/bin/node
COPY deploy/entrypoint.sh /usr/local/bin/privacynode-entrypoint
RUN chmod +x /usr/local/bin/privacynode-entrypoint
USER nodeuser
ENTRYPOINT ["/usr/local/bin/privacynode-entrypoint"]
