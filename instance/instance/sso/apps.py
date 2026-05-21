from django.apps import AppConfig


class SsoConfig(AppConfig):
    """SSO Keycloak (OpenID Connect) pour l'instance Modoboa Startup Pack."""

    name = "instance.sso"
    label = "instance_sso"
    verbose_name = "SSO Keycloak"
