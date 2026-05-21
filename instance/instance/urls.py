"""Routes de l'instance Modoboa de production."""
from django.conf import settings
from django.urls import include, path

from . import views

urlpatterns = [
    path("config.json", views.spa_config, name="spa-config"),
]

# SSO Keycloak — monté avant les routes Modoboa pour intercepter /oidc/.
if settings.SSO_ENABLED:
    urlpatterns += [path("oidc/", include("mozilla_django_oidc.urls"))]

urlpatterns += [path("", include("modoboa.urls"))]
