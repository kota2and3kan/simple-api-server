# syntax=docker/dockerfile:1

FROM golang:1.27-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
	-trimpath \
	-ldflags="-s -w" \
	-o /out/simple-api-server \
	.

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/simple-api-server /simple-api-server

ENV SIMPLE_API_SERVER_LISTEN_ADDR=0.0.0.0:8080

EXPOSE 8080 8443

USER nonroot:nonroot

ENTRYPOINT ["/simple-api-server"]
