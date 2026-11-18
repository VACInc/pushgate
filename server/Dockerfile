FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS admin-web

WORKDIR /admin-web
COPY admin-web/package*.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY admin-web ./
RUN npm run build

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

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
