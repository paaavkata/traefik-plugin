FROM golang:1.22 AS vendor

WORKDIR /plugin

COPY go.mod go.sum ./
COPY *.go ./

RUN go mod vendor

FROM traefik:v3.6.6

COPY --from=vendor /plugin /plugins-local/src/github.com/fileconvert/traefik-gateway-plugin/
