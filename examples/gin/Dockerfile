# syntax=docker/dockerfile:1
# Build context is the repository root:
#   docker build -f examples/gin/Dockerfile -t guard-example .
ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/guard-example ./examples/gin \
 && mkdir -p /out/app/migrations/guard

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /out/app /app
COPY --from=build /out/guard-example /usr/local/bin/guard-example
COPY examples/gin/guard.yaml /app/guard.yaml
# Settings live in /app/guard.yaml (GUARD_CONFIG); secrets come from the environment:
# DATABASE_URL, REDIS_ADDR, REDIS_PASSWORD, GUARD_ADMIN_EMAIL, GUARD_ADMIN_PASSWORD, GUARD_INSECURE_COOKIE
ENV ADDR=:8080 GUARD_CONFIG=/app/guard.yaml GIN_MODE=release
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/guard-example"]
