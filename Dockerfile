# syntax=docker/dockerfile:1

ARG APP_NAME=identity

FROM rustlang/rust:nightly-slim AS build
ARG APP_NAME
WORKDIR /app

RUN apt update && apt install -y pkg-config libssl-dev

RUN --mount=type=bind,source=src,target=src \
    --mount=type=bind,source=askama.toml,target=askama.toml \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    <<EOF
set -e
cargo build --locked --release
cp ./target/release/$APP_NAME /bin/server
EOF


FROM debian:bullseye-slim AS final


ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser
USER appuser

COPY --from=build /bin/server /bin/

EXPOSE 80

CMD ["/bin/server", "listen", "--bind", "0.0.0.0:80"]
