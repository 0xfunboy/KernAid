FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS builder

ENV PNPM_HOME=/pnpm
ENV PATH=/pnpm:$PATH

WORKDIR /workspace

RUN corepack enable
RUN corepack prepare pnpm@9.15.9 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/fleet-schemas/package.json packages/fleet-schemas/package.json
COPY services/fleet-control-plane/package.json services/fleet-control-plane/package.json
COPY apps/fleet-console/package.json apps/fleet-console/package.json

RUN pnpm install --frozen-lockfile --ignore-scripts

COPY packages/fleet-schemas/src packages/fleet-schemas/src
COPY packages/fleet-schemas/tsconfig.json packages/fleet-schemas/tsconfig.json
COPY services/fleet-control-plane/src services/fleet-control-plane/src
COPY services/fleet-control-plane/tsconfig.json services/fleet-control-plane/tsconfig.json
COPY services/fleet-control-plane/tsconfig.build.json services/fleet-control-plane/tsconfig.build.json
COPY apps/fleet-console/index.html apps/fleet-console/index.html
COPY apps/fleet-console/app.js apps/fleet-console/app.js
COPY apps/fleet-console/styles.css apps/fleet-console/styles.css

RUN pnpm --filter @kernaid/fleet-control-plane build
RUN pnpm --filter @kernaid/fleet-console check

FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS runtime

LABEL org.opencontainers.image.title="KernAid Fleet control plane" \
      org.opencontainers.image.description="Signed enrollment and privacy-bounded inventory registry" \
      org.opencontainers.image.version="0.1.0"

ENV NODE_ENV=production \
    TMPDIR=/tmp \
    KERNAID_FLEET_HOST=0.0.0.0 \
    KERNAID_FLEET_PORT=7341 \
    KERNAID_FLEET_DB_PATH=/var/lib/kernaid-fleet/fleet.sqlite \
    KERNAID_FLEET_ROOT_TOKEN_FILE=/run/secrets/kernaid_fleet_root_token \
    FLEET_CONSOLE_DIR=/opt/kernaid/console

WORKDIR /opt/kernaid

RUN install -d -o node -g node -m 0700 /var/lib/kernaid-fleet
RUN install -d -o root -g root -m 0755 \
      /opt/kernaid/services/fleet-control-plane \
      /opt/kernaid/node_modules/@kernaid/fleet-schemas \
      /opt/kernaid/console

COPY --from=builder /workspace/services/fleet-control-plane/dist \
  /opt/kernaid/services/fleet-control-plane/dist
COPY --from=builder /workspace/services/fleet-control-plane/package.json \
  /opt/kernaid/services/fleet-control-plane/package.json
COPY --from=builder /workspace/packages/fleet-schemas/dist \
  /opt/kernaid/node_modules/@kernaid/fleet-schemas/dist
COPY --from=builder /workspace/packages/fleet-schemas/package.json \
  /opt/kernaid/node_modules/@kernaid/fleet-schemas/package.json
COPY --from=builder /workspace/apps/fleet-console/index.html \
  /opt/kernaid/console/index.html
COPY --from=builder /workspace/apps/fleet-console/app.js \
  /opt/kernaid/console/app.js
COPY --from=builder /workspace/apps/fleet-console/styles.css \
  /opt/kernaid/console/styles.css

VOLUME ["/var/lib/kernaid-fleet"]
EXPOSE 7341
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:7341/healthz',{signal:AbortSignal.timeout(2000)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]

USER node:node

ENTRYPOINT ["node", "/opt/kernaid/services/fleet-control-plane/dist/main.js"]
