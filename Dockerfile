# Stage 1: Build Rust backend
FROM rust:1.86-slim-bookworm AS rust-builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release --bin decision-forum-server

# Stage 2: Build frontend
FROM node:20-slim AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=rust-builder /app/target/release/decision-forum-server /app/
COPY --from=web-builder /app/web/dist /app/web/dist
COPY crates/exo-gateway/migrations /app/migrations
ENV PORT=8080
ENV RUST_LOG=info
EXPOSE 8080
CMD ["./decision-forum-server"]
