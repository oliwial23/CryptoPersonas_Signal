# One Signal-Persona Desktop instance on a virtual display, viewable in a browser.
#
# Build from the CryptoPersonas_Signal root (the context needs both the Rust workspace and
# Signal-Desktop-Persona-main):
#
#   docker build -f deploy/play/Dockerfile -t personas-play .
#
# Three stages: the ZK addon (Rust nightly), the Desktop bundle (Node/pnpm), and a slim
# runtime with Xvfb + x11vnc + noVNC. Builds for the host's arch, so build it ON the VM
# (x86_64) rather than shipping an arm64 image from a Mac.

# ---------------------------------------------------------------------------------------
# 1. personas-node napi addon
# ---------------------------------------------------------------------------------------
FROM rust:1-bookworm AS engine
WORKDIR /src
# The toolchain file pins the nightly; copy it first so the toolchain install is cached.
COPY rust-toolchain.toml ./
RUN rustup show active-toolchain || rustup toolchain install
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY batch-zkc ./batch-zkc
# Cargo.toml [patch]es libsignal-service and presage to these paths; cargo wants them present.
COPY third_party ./third_party
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build -p personas-node --release \
 && cp target/release/libpersonas_node.so /personas-engine.node

# ---------------------------------------------------------------------------------------
# 2. Signal-Desktop-Persona bundle
# ---------------------------------------------------------------------------------------
FROM node:24.17.0-bookworm AS client
# libpulse0: ringrtc's native module links it, and build:db-schema loads ringrtc.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 build-essential git jq \
      libpulse0 \
 && rm -rf /var/lib/apt/lists/*
RUN corepack enable && corepack prepare pnpm@11.5.2 --activate
WORKDIR /app
COPY Signal-Desktop-Persona-main/ ./
# No .git in the context, so getBuildCreationTimestamp needs this or it shells out to git.
# The build expires 30-90 days after this timestamp; rebuild the image before then.
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    export SOURCE_DATE_EPOCH="$(date +%s)" \
 && pnpm install --frozen-lockfile \
 && pnpm run build:dev
# electron@43 fetches its binary lazily on first require rather than at install; do it now,
# while /app is still writable, instead of at runtime as the unprivileged user.
RUN node -e "require('electron')" && test -x node_modules/electron/dist/electron
# Same names build.sh produces, so index.cjs finds it on either arch.
COPY --from=engine /personas-engine.node /tmp/personas-engine.node
RUN case "$(uname -m)" in \
      x86_64)  cp /tmp/personas-engine.node packages/personas-engine/personas-engine.linux-x64.node ;; \
      aarch64) cp /tmp/personas-engine.node packages/personas-engine/personas-engine.linux-arm64.node ;; \
      *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;; \
    esac
# serverPublicParams of the personas test server, pulled from the Rust source the same way
# personas-demo-setup.sh does, so the entrypoint never has to guess it.
COPY third_party/libsignal-service-rs/src/configuration.rs /tmp/configuration.rs
RUN grep -hoE 'AAp8oB0D4EV2q7hSue3Kxzh1Vc88[A-Za-z0-9+/=]*' /tmp/configuration.rs \
      | awk '{ print length, $0 }' | sort -rn | head -1 | cut -d' ' -f2- > /app/config/.server-public-params \
 && test "$(wc -c < /app/config/.server-public-params)" -gt 600 \
 && rm /tmp/configuration.rs

# ---------------------------------------------------------------------------------------
# 3. Runtime: Electron on Xvfb, exported over noVNC
# ---------------------------------------------------------------------------------------
FROM node:24.17.0-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      xvfb x11vnc openbox novnc websockify dbus-x11 jq procps ca-certificates openssl \
      libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libgbm1 libgtk-3-0 \
      libasound2 libpulse0 libxss1 libxshmfence1 libxkbcommon0 libsecret-1-0 libnotify4 \
      fonts-dejavu-core fonts-noto-color-emoji \
 && rm -rf /var/lib/apt/lists/*
COPY --from=client /app /app
COPY deploy/play/entrypoint.sh /usr/local/bin/personas-play
COPY deploy/play/tls-relay.js /usr/local/lib/personas/tls-relay.js
# Electron's sandbox needs user namespaces, which rootless/containerised runs often lack;
# running as an unprivileged user plus --no-sandbox is the usual container compromise.
RUN useradd -m -u 1000 -s /bin/bash member 2>/dev/null || useradd -m -s /bin/bash member; \
    chmod +x /usr/local/bin/personas-play \
 && mkdir -p /shared/roster /shared/keys && chown -R member /shared /app/config \
 && mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix
USER member
ENV HOME=/home/member \
    DISPLAY=:1 \
    PERSONAS_ROSTER_DIR=/shared/roster \
    PERSONAS_KEYS_DIR=/shared/keys
EXPOSE 6080
ENTRYPOINT ["/usr/local/bin/personas-play"]
