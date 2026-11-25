FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS admin-web

WORKDIR /admin-web
COPY admin-web/package*.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY admin-web ./
RUN npm run build

FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml LICENSE NOTICE ./
COPY requirements.lock ./
COPY server ./server
COPY sdk ./sdk
COPY pam ./pam
COPY --from=admin-web /admin-web/dist ./admin-web
RUN pip install --require-hashes --only-binary=:all: -r requirements.lock \
    && pip install --no-build-isolation --no-deps .
RUN groupadd --system pushgate \
    && useradd --system --gid pushgate --home-dir /nonexistent --shell /usr/sbin/nologin pushgate \
    && install -d --owner=pushgate --group=pushgate --mode=0700 /var/lib/pushgate
# Use a private SQLite default; deployment environment settings can override it.
ENV PUSHGATE_DATABASE_URL=sqlite:////var/lib/pushgate/pushgate.db \
    PUSHGATE_STATIC_DIR=/app/admin-web
USER pushgate
EXPOSE 8000
CMD ["uvicorn", "server.app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
