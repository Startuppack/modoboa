"""
Réglages Django de l'instance Modoboa de production (Startup Pack).

Tout est piloté par variables d'environnement — aucun secret en dur. Le seul
écart fonctionnel vis-à-vis d'une instance Modoboa standard est le SSO : quand
`SSO_ENABLED=true`, l'authentification est fédérée vers le realm Keycloak
`startuppack` (OpenID Connect), avec `kc_idp_hint` dynamique pour rebondir
directement sur le realm du client. Cf. instance/sso/.
"""
import os
from logging.handlers import SysLogHandler


def env(key, default=None):
    return os.environ.get(key, default)


def env_bool(key, default=False):
    return os.environ.get(key, str(default)).lower() in ("1", "true", "yes", "on")


def env_list(key, default=""):
    return [v.strip() for v in os.environ.get(key, default).split(",") if v.strip()]


BASE_DIR = os.path.realpath(os.path.dirname(os.path.dirname(__file__)))

# SECURITY ------------------------------------------------------------------
SECRET_KEY = env("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY est obligatoire (variable d'environnement).")

DEBUG = env_bool("DEBUG", False)

ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", "localhost,127.0.0.1")
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS")
INTERNAL_IPS = ["127.0.0.1"]
SITE_ID = 1
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# Derrière le reverse-proxy Traefik (TLS terminé en amont).
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
X_FRAME_OPTIONS = "SAMEORIGIN"

# APPS ----------------------------------------------------------------------
INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.sites",
    "django.contrib.staticfiles",
    "reversion",
    "oauth2_provider",
    "corsheaders",
    "rest_framework",
    "rest_framework.authtoken",
    "django_filters",
    "drf_spectacular",
    "django_otp",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    "django_rename_app",
    "django_rq",
)

MODOBOA_APPS = (
    "modoboa",
    "modoboa.core",
    "modoboa.lib",
    "modoboa.admin",
    "modoboa.autoconfig",
    "modoboa.transport",
    "modoboa.relaydomains",
    "modoboa.limits",
    "modoboa.parameters",
    "modoboa.dnstools",
    "modoboa.policyd",
    "modoboa.maillog",
    "modoboa.pdfcredentials",
    "modoboa.dmarc",
    "modoboa.imap_migration",
    "modoboa.autoreply",
    "modoboa.sievefilters",
    "modoboa.contacts",
    "modoboa.calendars",
    "modoboa.webmail",
    "modoboa.amavis",
)

try:
    import ldap  # noqa: F401
except ImportError:
    pass
else:
    MODOBOA_APPS += ("modoboa.ldapsync",)

INSTALLED_APPS += MODOBOA_APPS

AUTH_USER_MODEL = "core.User"

# SSO Keycloak (OpenID Connect) — activé conditionnellement.
SSO_ENABLED = env_bool("SSO_ENABLED", False)
if SSO_ENABLED:
    INSTALLED_APPS += ("mozilla_django_oidc", "instance.sso")

MIDDLEWARE = (
    "django.contrib.sessions.middleware.SessionMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "x_forwarded_for.middleware.XForwardedForMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "modoboa.core.middleware.LocalConfigMiddleware",
    "modoboa.lib.middleware.CommonExceptionCatcher",
    "modoboa.lib.middleware.RequestCatcherMiddleware",
)

AUTHENTICATION_BACKENDS = ()
if SSO_ENABLED:
    AUTHENTICATION_BACKENDS += ("instance.sso.auth.KeycloakOIDCBackend",)
AUTHENTICATION_BACKENDS += (
    "django.contrib.auth.backends.ModelBackend",
    "modoboa.imap_migration.auth_backends.IMAPBackend",
)

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
                "modoboa.core.context_processors.theme",
            ],
            "debug": DEBUG,
        },
    },
]

ROOT_URLCONF = "instance.urls"
WSGI_APPLICATION = "instance.wsgi.application"

# DATABASE ------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("DB_NAME", "modoboa"),
        "USER": env("DB_USER", "modoboa"),
        "PASSWORD": env("DB_PASSWORD", ""),
        "HOST": env("DB_HOST", "127.0.0.1"),
        "PORT": env("DB_PORT", "5432"),
        "ATOMIC_REQUESTS": True,
        "CONN_MAX_AGE": 60,
        "OPTIONS": {
            "client_encoding": "UTF8",
            "sslmode": env("DB_SSLMODE", "prefer"),
        },
    },
}

# CORS ----------------------------------------------------------------------
CORS_ORIGIN_ALLOW_ALL = False
CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS")

# I18N ----------------------------------------------------------------------
LANGUAGE_CODE = env("LANGUAGE_CODE", "fr")
TIME_ZONE = env("TIME_ZONE", "Europe/Paris")
USE_I18N = True
USE_L10N = True
USE_TZ = True

# STATIC / MEDIA ------------------------------------------------------------
STATIC_URL = "/sitestatic/"
STATIC_ROOT = env("STATIC_ROOT", os.path.join(BASE_DIR, "sitestatic"))
MEDIA_URL = "/media/"
MEDIA_ROOT = env("MEDIA_ROOT", os.path.join(BASE_DIR, "media"))
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    },
}

# E-MAIL --------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST", "localhost")
EMAIL_PORT = int(env("EMAIL_PORT", "25"))
EMAIL_HOST_USER = env("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = env_bool("EMAIL_USE_TLS", False)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", "postmaster@startuppack.eu")

EMAIL_CLIENT_CONNECTION_SETTINGS = {
    "imap": {
        "HOSTNAME": env("IMAP_HOST", "dovecot"),
        "SOCKET_TYPE": env("IMAP_SOCKET_TYPE", "SSL"),
        "PORT": int(env("IMAP_PORT", "993")),
    },
    "smtp": {
        "HOSTNAME": env("SMTP_HOST", "postfix"),
        "SOCKET_TYPE": env("SMTP_SOCKET_TYPE", "STARTTLS"),
        "PORT": int(env("SMTP_PORT", "587")),
    },
}

# OAUTH2 / OIDC PROVIDER (frontend Vue ↔ API Modoboa) -----------------------
OIDC_RSA_PRIVATE_KEY = env("OIDC_RSA_PRIVATE_KEY", "")
OAUTH2_PROVIDER = {
    "OIDC_ENABLED": True,
    "OIDC_RP_INITIATED_LOGOUT_ENABLED": True,
    "OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT": False,
    "OIDC_RSA_PRIVATE_KEY": OIDC_RSA_PRIVATE_KEY,
    "SCOPES": {
        "openid": "OpenID Connect scope",
        "read": "Read scope",
        "write": "Write scope",
        "introspection": "Introspect token scope",
    },
    "DEFAULT_SCOPES": ["openid", "read", "write"],
}

REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_RATES": {
        "user": "400/minute",
        "ddos": "50/second",
        "ddos_lesser": "200/minute",
        "login": "10/minute",
        "password_recovery_request": "12/hour",
        "password_recovery_totp_check": "25/hour",
        "password_recovery_apply": "25/hour",
    },
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "oauth2_provider.contrib.rest_framework.OAuth2Authentication",
        "rest_framework.authentication.TokenAuthentication",
    ),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_VERSIONING_CLASS": "rest_framework.versioning.NamespaceVersioning",
}

SPECTACULAR_SETTINGS = {
    "SCHEMA_PATH_PREFIX": r"/api/v[0-9]",
    "TITLE": "Modoboa API",
    "VERSION": None,
    "SERVE_AUTHENTICATION": [],
    "DEFAULT_FILTER_INSPECTORS": [
        "drf_spectacular.contrib.django_filters.DjangoFilterBackendInspector",
    ],
}

# REDIS / RQ / CACHE --------------------------------------------------------
REDIS_SENTINEL = env_bool("REDIS_SENTINEL", False)
REDIS_SENTINELS = [
    (env("REDIS_SENTINEL_HOST", "127.0.0.1"), env("REDIS_SENTINEL_PORT", 26379))
]
REDIS_MASTER = env("REDIS_MASTER", "mymaster")
REDIS_HOST = env("REDIS_HOST", "127.0.0.1")
REDIS_PORT = env("REDIS_PORT", "6379")
REDIS_QUOTA_DB = 0
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_QUOTA_DB}"

RQ = {"COMMIT_MODE": "auto"}
RQ_QUEUES = {
    "dkim": {"URL": REDIS_URL},
    "modoboa": {"URL": REDIS_URL},
    "dovecot": {"URL": REDIS_URL},
}
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": f"redis://{REDIS_HOST}:{REDIS_PORT}",
    }
}

# PASSWORD VALIDATION -------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    {
        "NAME": "modoboa.core.password_validation.ComplexityValidator",
        "OPTIONS": {"upper": 1, "lower": 1, "digits": 1, "specials": 0},
    },
]

# MODOBOA -------------------------------------------------------------------
DOVECOT_USER = env("DOVECOT_USER", "root")
MODOBOA_API_URL = "https://api.modoboa.org/1/"
PID_FILE_STORAGE_PATH = "/tmp"
DISABLE_DASHBOARD_EXTERNAL_QUERIES = env_bool("DISABLE_DASHBOARD_EXTERNAL_QUERIES", False)
LDAP_SERVER_PORT = env("LDAP_SERVER_PORT", 3389)
WEBMAIL_DEV_MODE = False

# AMAVIS --------------------------------------------------------------------
DATABASE_ROUTERS = ["modoboa.amavis.dbrouter.AmavisRouter"]
AMAVIS_DEFAULT_DATABASE_ENCODING = "UTF-8"
if env("AMAVIS_DB_HOST"):
    DATABASES["amavis"] = {
        "ENGINE": "django.db.backends.mysql",
        "HOST": env("AMAVIS_DB_HOST"),
        "PORT": env("AMAVIS_DB_PORT", "3306"),
        "NAME": env("AMAVIS_DB_NAME", "amavis"),
        "USER": env("AMAVIS_DB_USER", "amavis"),
        "PASSWORD": env("AMAVIS_DB_PASSWORD", ""),
    }
else:  # pas d'Amavis configuré → l'app reste installée mais sans base dédiée.
    DATABASES["amavis"] = dict(DATABASES["default"])

# LOGGING (tout sur stdout — collecté par k8s) ------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "syslog": {"format": "%(name)s: %(levelname)s %(message)s"},
        "django.server": {
            "()": "django.utils.log.ServerFormatter",
            "format": "[%(server_time)s] %(message)s",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "syslog"},
        "modoboa": {"class": "modoboa.core.loggers.SQLHandler"},
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": "ERROR", "propagate": False},
        "modoboa.auth": {"handlers": ["console", "modoboa"], "level": "INFO", "propagate": False},
        "modoboa.admin": {"handlers": ["modoboa"], "level": "INFO", "propagate": False},
        "modoboa.dns": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "modoboa.jobs": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "instance.sso": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}

SILENCED_SYSTEM_CHECKS = [
    "security.W019",  # Modoboa affiche les e-mails dans des iframes.
    "fields.W342",
]

# ── SSO Keycloak (OpenID Connect, RP) ──────────────────────────────────────
if SSO_ENABLED:
    KEYCLOAK_URL = env("KEYCLOAK_URL", "").rstrip("/")
    SSO_REALM = env("SSO_REALM", "startuppack")
    _oidc_base = f"{KEYCLOAK_URL}/realms/{SSO_REALM}/protocol/openid-connect"

    OIDC_RP_CLIENT_ID = env("OIDC_RP_CLIENT_ID", "modoboa")
    OIDC_RP_CLIENT_SECRET = env("OIDC_RP_CLIENT_SECRET", "")
    OIDC_RP_SIGN_ALGO = "RS256"
    OIDC_RP_SCOPES = "openid email profile"

    OIDC_OP_AUTHORIZATION_ENDPOINT = f"{_oidc_base}/auth"
    OIDC_OP_TOKEN_ENDPOINT = f"{_oidc_base}/token"
    OIDC_OP_USER_ENDPOINT = f"{_oidc_base}/userinfo"
    OIDC_OP_JWKS_ENDPOINT = f"{_oidc_base}/certs"
    OIDC_OP_LOGOUT_ENDPOINT = f"{_oidc_base}/logout"

    # Vue d'auth maison : injecte un kc_idp_hint dynamique (realm du client).
    OIDC_AUTHENTICATE_CLASS = "instance.sso.views.IdpHintAuthRequestView"
    OIDC_OP_LOGOUT_URL_METHOD = "instance.sso.views.keycloak_logout_url"

    # Provisionnement piloté par le token (cf. instance/sso/auth.py) :
    #  • domaine principal      = domaine de l'e-mail ;
    #  • rôle                   = rôles client `modoboa` dans le token ;
    #  • domaines administrés   = attribut multivalué SSO_DOMAINS_CLAIM.
    OIDC_CREATE_USER = env_bool("SSO_PROVISION", False)
    SSO_PROVISION = env_bool("SSO_PROVISION", False)
    SSO_DOMAINADMIN_ROLES = env_list("SSO_DOMAINADMIN_ROLES", "domainadmin")
    SSO_SUPERADMIN_ROLES = env_list("SSO_SUPERADMIN_ROLES", "superadmin")
    # Attributs Keycloak dédiés (le claim `email` standard = e-mail perso).
    SSO_EMAIL_CLAIM = env("SSO_EMAIL_CLAIM", "modoboa_email")
    SSO_ALIASES_CLAIM = env("SSO_ALIASES_CLAIM", "modoboa_aliases")
    SSO_DOMAINS_CLAIM = env("SSO_DOMAINS_CLAIM", "modoboa_domains")
    OIDC_STORE_ID_TOKEN = True

    LOGIN_URL = "/oidc/authenticate/"
    LOGIN_REDIRECT_URL = "/"
    LOGOUT_REDIRECT_URL = "/"
