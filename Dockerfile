FROM golang:1.22-alpine3.20 AS build
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

# --mount option requires buildx enabled (DOCKER_BUILDKIT=1 docker compose build)
# https://docs.docker.com/build/buildkit/#getting-started
RUN --mount=type=cache,target="/root/.cache/go-build" CGO_ENABLED=0 GOOS=linux go build -o /app/build
# RUN CGO_ENABLED=0 GOOS=linux go build -o /app/build

FROM alpine:3.20 AS final
WORKDIR /app
COPY --from=build /app/build .

EXPOSE 8080
CMD ["/app/build"]