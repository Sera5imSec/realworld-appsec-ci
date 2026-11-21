FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /realworld .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app /data && chown 10001:10001 /app /data
COPY --from=build /realworld /app/realworld
USER 10001:10001
WORKDIR /app
ENV GIN_MODE=release PORT=8080 DB_PATH=/data/gorm.db
EXPOSE 8080
CMD ["/app/realworld"]
