# SecuScan — image de production : API FastAPI + interface compilée, servies par un seul processus.
# Construction :  docker build -t secuscan .
# Voir docs/deploiement.md (HTTPS avec Caddy, variables, sauvegardes).

# --- 1. Interface web (React + Vite) ------------------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /src/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
RUN npm run build

# --- 2. API Python ------------------------------------------------------------------------------
FROM python:3.12-slim AS app
# git : clonage des dépôts à analyser ; aucun outil de compilation n'est conservé dans l'image
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv

WORKDIR /app/apps/api
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv
COPY apps/api/pyproject.toml apps/api/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY apps/api/secuscan ./secuscan
COPY demo /app/demo
COPY --from=web /src/apps/web/dist /app/apps/web/dist

# Utilisateur sans privilèges ; /data : base SQLite, cache IA, réglages de l'écran « Paramètres »
# (/data/work créé ici avec le bon propriétaire : Docker recopie ces droits dans un volume neuf)
RUN useradd --create-home --uid 10001 secuscan \
    && mkdir -p /data/work/.sandbox && chown -R secuscan /data
USER secuscan
ENV PATH=/opt/venv/bin:$PATH \
    SECUSCAN_DATA_DIR=/data \
    SECUSCAN_ENV_FILE=/data/secuscan.env \
    SECUSCAN_PRODUCTION=true \
    SECUSCAN_COOKIE_SECURE=true \
    FORWARDED_ALLOW_IPS=127.0.0.1
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"

# API ; avec SECUSCAN_QUEUE=worker, les analyses tournent dans le service « worker » (docker-compose)
CMD ["sh", "-c", "exec uvicorn secuscan.main:app --host 0.0.0.0 --port 8000 --workers 1 --proxy-headers --forwarded-allow-ips \"$FORWARDED_ALLOW_IPS\""]
