# Multi-stage: build a static binary, ship it on a minimal image.
#   docker build -t onlinepresence .
#   docker run --rm -p 8080:8080 onlinepresence                 # REST API
#   docker run --rm -p 8090:8090 -e MCP_LISTEN_ADDR=0.0.0.0:8090 \
#     onlinepresence serve-mcp                                  # MCP over HTTP
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /onlinepresence-server ./cmd/onlinepresence-server

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=build /onlinepresence-server /usr/local/bin/onlinepresence-server
USER nobody
EXPOSE 8080 8090
ENTRYPOINT ["onlinepresence-server"]
CMD ["serve"]
