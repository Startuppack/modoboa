"""Routes de l'instance Modoboa de production."""
from django.conf import settings
from django.urls import include, path

from . import views

urlpatterns = [
    path("config.json", views.spa_config, name="spa-config"),
]

# SSO Keycloak — monté avant les routes Modoboa pour intercepter /oidc/.
if settings.SSO_ENABLED:
    from .sso.views import federated_logout

    urlpatterns += [
        path("oidc/", include("mozilla_django_oidc.urls")),
        # Logout fédéré GET-able (Roundcube → Modoboa → Keycloak), cf. sso/views.
        path("sso/logout/", federated_logout, name="federated-logout"),
    ]

urlpatterns += [path("", include("modoboa.urls"))]
