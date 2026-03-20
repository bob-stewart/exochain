FROM node:20-alpine
WORKDIR /app

# Install WASM package + pg + tsx
COPY packages/exochain-wasm/ /app/packages/exochain-wasm/
RUN echo '{"type":"module","dependencies":{"pg":"^8.13.0","tsx":"^4.19.0"}}' > package.json && \
    npm install --production 2>/dev/null

# Make WASM accessible
RUN ln -sf /app/packages /packages && \
    mkdir -p /app/node_modules/@exoeth && \
    ln -sf /app/packages/exochain-wasm /app/node_modules/@exoeth/exochain-wasm

# Copy gateway service code
COPY services/gateway-api/ /app/

ENV NODE_ENV=production
CMD ["npx", "tsx", "src/server.ts"]
