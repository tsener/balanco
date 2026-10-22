FROM rust:1.90-alpine AS build
RUN apk add --no-cache build-base cmake perl linux-headers binutils
WORKDIR /work
COPY Cargo.toml Cargo.lock LICENSE .dockerignore ./
COPY src ./src
COPY examples ./examples
COPY deploy/container/Dockerfile ./deploy/container/Dockerfile
ENV RUSTFLAGS="-C target-feature=+crt-static"
# An explicit target keeps static target flags off host proc-macro builds.
RUN cargo build --locked --release --bins --target x86_64-unknown-linux-musl \
    && ! readelf -l target/x86_64-unknown-linux-musl/release/balanco | grep 'interpreter' \
    && ! readelf -d target/x86_64-unknown-linux-musl/release/balanco | grep NEEDED \
    && ! readelf -l target/x86_64-unknown-linux-musl/release/balanco-controller | grep 'interpreter' \
    && ! readelf -d target/x86_64-unknown-linux-musl/release/balanco-controller | grep NEEDED \
    && target/x86_64-unknown-linux-musl/release/balanco --version \
    && tar -czf /balanco-source.tar.gz Cargo.toml Cargo.lock LICENSE src examples deploy .dockerignore \
    && mkdir -p /runtime/run/balanco
RUN chmod 0700 /runtime/run/balanco

FROM scratch
LABEL org.opencontainers.image.title="Balanco" \
      org.opencontainers.image.description="TCP/mTLS proxy for IoT and WebSockets" \
      org.opencontainers.image.source="https://github.com/tsener/balanco" \
      org.opencontainers.image.licenses="GPL-3.0-only"
COPY --from=build /work/target/x86_64-unknown-linux-musl/release/balanco /work/target/x86_64-unknown-linux-musl/release/balanco-controller /bin/
COPY --from=build /work/LICENSE /usr/share/licenses/balanco/LICENSE
COPY --from=build /balanco-source.tar.gz /usr/share/balanco/source.tar.gz
COPY --from=build --chown=65532:65532 /runtime/run/ /run/
USER 65532:65532
EXPOSE 8443 9443
STOPSIGNAL SIGTERM
ENTRYPOINT ["/bin/balanco"]
CMD ["--help"]
