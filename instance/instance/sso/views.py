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
from urllib.parse import urlencode, urlparse

from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.http import HttpResponseRedirect

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


def _safe_post_logout(request):
    """Destination finale après déconnexion, validée contre `ALLOWED_HOSTS`
    (anti open-redirect). À défaut : `LOGOUT_REDIRECT_URL`."""
    nxt = request.GET.get("next") or request.GET.get("post_logout")
    if nxt:
        host = urlparse(nxt).netloc.split(":")[0]
        if host and host in set(getattr(settings, "ALLOWED_HOSTS", [])):
            return nxt
    return request.build_absolute_uri(getattr(settings, "LOGOUT_REDIRECT_URL", "/"))


def federated_logout(request):
    """Déconnexion fédérée déclenchable en simple **GET** (redirection).

    L'`/oidc/logout/` de mozilla-django-oidc est POST-only, donc inutilisable
    par un client en aval (Roundcube) qui ne sait que rediriger le navigateur.
    Cette vue : (1) lit l'`id_token` AVANT de purger la session, (2) termine la
    session Django Modoboa, (3) rebondit sur l'end-session Keycloak — fermant
    ainsi les TROIS couches (Roundcube → Modoboa → Keycloak) et empêchant la
    réauthentification silencieuse sur l'identité précédente.
    """
    endpoint = getattr(settings, "OIDC_OP_LOGOUT_ENDPOINT", "")
    final = _safe_post_logout(request)
    id_token = request.session.get("oidc_id_token")
    auth_logout(request)
    if not endpoint:
        return HttpResponseRedirect(final)
    query = {"client_id": settings.OIDC_RP_CLIENT_ID, "post_logout_redirect_uri": final}
    if id_token:
        query["id_token_hint"] = id_token
    logger.info("SSO : federated_logout → Keycloak end-session (next=%s)", final)
    return HttpResponseRedirect(f"{endpoint}?{urlencode(query)}")
