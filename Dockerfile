FROM golang:1.25-alpine AS builder
WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG GO_BUILD_TAGS=""
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags "${GO_BUILD_TAGS}" -trimpath -ldflags="-s -w" -o /out/xconnect-controller ./cmd/xconnect-controller

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 -H appuser
USER 10001
WORKDIR /app
COPY --from=builder /out/xconnect-controller /usr/local/bin/xconnect-controller

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/xconnect-controller"]
