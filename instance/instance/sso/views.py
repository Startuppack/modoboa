"""
Vues SSO — démarrage de l'authentification OIDC et déconnexion Keycloak.

`IdpHintAuthRequestView` ajoute un `kc_idp_hint` dynamique à la requête
d'autorisation : le realm `startuppack` fédère un realm par client, et ce
paramètre fait rebondir Keycloak directement sur le bon fournisseur d'identité
(le realm du client), sans écran de sélection. La plateforme d'onboarding
construit donc le lien Modoboa sous la forme :

    https://mail.startuppack.eu/oidc/authenticate/?realm=<idp-alias-client>
"""
import logging
from urllib.parse import urlencode

from django.conf import settings

from mozilla_django_oidc.views import OIDCAuthenticationRequestView

logger = logging.getLogger("instance.sso")

# Paramètres de requête acceptés pour désigner le realm/IdP du client.
_HINT_PARAMS = ("kc_idp_hint", "realm", "idp")


class IdpHintAuthRequestView(OIDCAuthenticationRequestView):
    """Démarre le flux OIDC en propageant un `kc_idp_hint` éventuel."""

    def get_extra_params(self, request):
        params = super().get_extra_params(request)
        for key in _HINT_PARAMS:
            hint = request.GET.get(key)
            if hint:
                params["kc_idp_hint"] = hint.strip()
                logger.info("SSO : kc_idp_hint=%s", hint.strip())
                break
        return params


def keycloak_logout_url(request):
    """
    URL de fin de session Keycloak (RP-initiated logout). Branchée via
    `OIDC_OP_LOGOUT_URL_METHOD` : déconnecte aussi la session Keycloak, pas
    seulement la session Modoboa.
    """
    endpoint = getattr(settings, "OIDC_OP_LOGOUT_ENDPOINT", "")
    if not endpoint:
        return getattr(settings, "LOGOUT_REDIRECT_URL", "/")
    query = {"client_id": settings.OIDC_RP_CLIENT_ID}
    id_token = request.session.get("oidc_id_token")
    if id_token:
        query["id_token_hint"] = id_token
    redirect = request.build_absolute_uri(getattr(settings, "LOGOUT_REDIRECT_URL", "/"))
    query["post_logout_redirect_uri"] = redirect
    return f"{endpoint}?{urlencode(query)}"
