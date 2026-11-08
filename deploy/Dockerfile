FROM --platform=$BUILDPLATFORM node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY tokens.css /src/tokens.css
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS go
ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY migrations/ ./migrations/
COPY --from=ui /src/internal/ui/dist/ ./internal/ui/dist/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -tags=release -ldflags='-s -w' -o /out/cheesetrap ./cmd/cheesetrap

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime
COPY --from=go /out/cheesetrap /usr/local/bin/cheesetrap
# Verify registry TLS with the builder image's maintained public CA bundle.
COPY --from=go /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/cheesetrap/
COPY third_party/ /usr/share/doc/cheesetrap/third_party/
COPY --from=go /usr/share/doc/ca-certificates/copyright /usr/share/doc/cheesetrap/ca-certificates-copyright
LABEL org.opencontainers.image.title="cheesetrap"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/cheesetrap"]
CMD ["help"]
