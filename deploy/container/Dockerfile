FROM rust:1.90-alpine AS build
RUN apk add --no-cache build-base cmake perl linux-headers binutils openssl
WORKDIR /work
COPY Cargo.toml Cargo.lock LICENSE .dockerignore ./
COPY src ./src
COPY examples ./examples
ENV RUSTFLAGS="-C target-feature=+crt-static"
# An explicit target keeps static target flags off host proc-macro builds.
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64) target=x86_64-unknown-linux-musl ;; \
      aarch64) target=aarch64-unknown-linux-musl ;; \
      *) echo "Unsupported build architecture" >&2; exit 1 ;; \
    esac; \
    cargo test --locked --all-targets --target "$target"; \
    cargo build --locked --release --bins --target "$target"; \
    mkdir -p /out /runtime/run/balanco; \
    cp "target/$target/release/balanco" "target/$target/release/balanco-controller" /out/; \
    for binary in /out/balanco /out/balanco-controller; do \
      readelf -l "$binary" > /tmp/program-headers; \
      readelf -d "$binary" > /tmp/dynamic-section; \
      if grep -q interpreter /tmp/program-headers; then exit 1; fi; \
      if grep -q NEEDED /tmp/dynamic-section; then exit 1; fi; \
    done; \
    /out/balanco --version; \
    chmod 0700 /runtime/run/balanco
COPY deploy/container/Dockerfile ./deploy/container/Dockerfile
RUN tar -czf /balanco-source.tar.gz Cargo.toml Cargo.lock LICENSE src examples deploy .dockerignore

FROM scratch
LABEL org.opencontainers.image.title="Balanco" \
      org.opencontainers.image.description="TCP/mTLS proxy for IoT and WebSockets" \
      org.opencontainers.image.source="https://github.com/tsener/balanco" \
      org.opencontainers.image.licenses="GPL-3.0-only"
COPY --from=build /out/balanco /out/balanco-controller /bin/
COPY --from=build /work/LICENSE /usr/share/licenses/balanco/LICENSE
COPY --from=build /balanco-source.tar.gz /usr/share/balanco/source.tar.gz
COPY --from=build --chown=65532:65532 /runtime/run/ /run/
USER 65532:65532
EXPOSE 8443 9443
STOPSIGNAL SIGTERM
ENTRYPOINT ["/bin/balanco"]
CMD ["--help"]
