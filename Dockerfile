FROM rust:1.82-slim-bookworm as build
RUN apt update -qy
RUN apt install -qy librocksdb-dev clang cmake
# For openssl
RUN apt install -qy pkg-config libssl-dev ca-certificates build-essential
# RUN apt install -qy git cargo clang cmake

WORKDIR /build
COPY . .

RUN cargo build --release --bin electrs

FROM debian:bookworm-slim as deploy

RUN apt update -qy
RUN apt install -qy librocksdb-dev
RUN apt install -qy pkg-config libssl-dev ca-certificates build-essential
COPY --from=build /build/target/release/electrs /bin/electrs

EXPOSE 50001

ENTRYPOINT ["/bin/electrs"]