# syntax=docker/dockerfile:1
#
# Image de PRODUCTION de l'instance Modoboa Startup Pack — backend Django.
# Sert : l'API v2, le provider OAuth2/OIDC, les pages d'auth, le SSO Keycloak.
# La même image fait tourner les workers RQ et le policy daemon (commande
# surchargée côté k8s).
#
# Build context = racine du dépôt.  ->  docker build -f docker/Dockerfile .

# ── 1. Build de la SPA Vue (génère modoboa/frontend_dist) ──────────────────
FROM node:20-alpine AS spa
WORKDIR /build/frontend
COPY frontend/ ./
RUN yarn install --frozen-lockfile --network-timeout 600000 \
    && yarn build
# vite `outDir` = ../modoboa/frontend_dist  ->  /build/modoboa/frontend_dist

# ── 2. Build des dépendances Python ────────────────────────────────────────
FROM python:3.13-alpine AS build
ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    SETUPTOOLS_SCM_PRETEND_VERSION=2.4.0
RUN apk add --no-cache --update \
        openssl librrd python3-dev libffi-dev gcc g++ musl-dev \
        libxml2-dev libxslt-dev openssl-dev jpeg-dev rrdtool-dev file make \
        gettext freetype-dev cairo-dev cargo git mariadb-dev openldap-dev
RUN python3 -m venv $VIRTUAL_ENV && pip install -U 'pip<26' setuptools wheel
WORKDIR /src
COPY . /src
# Modoboa + driver Postgres + driver MySQL (Amavis) + WSGI + statiques + SSO.
RUN pip install ".[postgresql,mysql]" gunicorn whitenoise mozilla-django-oidc

# ── 3. Image finale ────────────────────────────────────────────────────────
FROM python:3.13-alpine AS run
ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DJANGO_SETTINGS_MODULE=instance.settings
RUN apk add --no-cache --update \
        openssl librrd libxslt libjpeg rrdtool libmagic libldap \
        mariadb-connector-c freetype gettext tini \
    && adduser -D -u 1000 modoboa

COPY --from=build $VIRTUAL_ENV $VIRTUAL_ENV
COPY docker/doveadm /usr/local/bin/doveadm
RUN chmod +x /usr/local/bin/doveadm

WORKDIR /app
# Source Modoboa (placée sur PYTHONPATH : prime sur la copie du venv et
# expose frontend_dist, requis par load_initial_data).
COPY modoboa/ /app/modoboa/
COPY --from=spa /build/modoboa/frontend_dist/ /app/modoboa/frontend_dist/
COPY instance/ /app/

RUN mkdir -p /app/sitestatic /app/media /app/frontend \
    && SECRET_KEY=build-only python manage.py collectstatic --noinput \
    && SECRET_KEY=build-only python manage.py compilemessages >/dev/null 2>&1 || true \
    && chown -R modoboa:modoboa /app

USER modoboa
EXPOSE 8000
ENTRYPOINT ["tini", "--"]
CMD ["gunicorn", "--chdir", "/app", "--bind", "0.0.0.0:8000", \
     "--workers", "3", "--timeout", "120", "--access-logfile", "-", \
     "instance.wsgi:application"]
