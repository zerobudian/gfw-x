# GFW X - multi-stage build.
# Stage 1: build the React+TS dashboard.
FROM node:20-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm install
COPY web/ .
RUN npm run build

# Stage 2: build the Go binary (frontend is embedded into the binary).
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY --from=web /src/internal/api/dist ./internal/api/dist
COPY . .
# COPY web dist via the stage that produced internal/api/dist; the source layout
# writes dist into internal/api/dist (see web/vite.config.ts).
ARG VERSION=0.1.0
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X gfw-x/internal/version.Version=${VERSION}" \
    -o /out/gfwx ./cmd/gfwx

# Stage 3: minimal runtime image.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/gfwx /usr/local/bin/gfwx
COPY configs/ ./configs/
# Runtime volume for logs / config.
VOLUME ["/app/data"]
EXPOSE 8443
ENV GFWX_UID=1000
ENTRYPOINT ["gfwx"]
CMD ["run", "--config", "configs/config.yaml"]