"""
Backend d'authentification OpenID Connect — fédération vers Keycloak.

Les comptes mail Modoboa sont provisionnés en amont (par l'administration
Modoboa ou la plateforme d'onboarding Startup Pack). Le SSO ne fait donc que
*relier* une identité Keycloak à un compte Modoboa existant, via l'e-mail.
La création automatique de compte reste possible (SSO_CREATE_USER=true) mais
n'est pas le mode nominal.
"""
import logging

from django.core.exceptions import SuspiciousOperation

from mozilla_django_oidc.auth import OIDCAuthenticationBackend

logger = logging.getLogger("instance.sso")


class KeycloakOIDCBackend(OIDCAuthenticationBackend):
    """Relie un jeton Keycloak à un utilisateur Modoboa (`core.User`)."""

    def verify_claims(self, claims):
        """Un e-mail vérifié est indispensable pour relier le compte."""
        return bool(claims.get("email"))

    def filter_users_by_claims(self, claims):
        """Recherche le compte Modoboa correspondant à l'e-mail Keycloak."""
        email = (claims.get("email") or "").strip().lower()
        if not email:
            return self.UserModel.objects.none()
        # username == e-mail pour les boîtes Modoboa ; on couvre les deux.
        return self.UserModel.objects.filter(email__iexact=email) | \
            self.UserModel.objects.filter(username__iexact=email)

    def create_user(self, claims):
        """Crée un compte Modoboa minimal (uniquement si SSO_CREATE_USER)."""
        email = (claims.get("email") or "").strip().lower()
        user = self.UserModel(username=email, email=email)
        user.set_unusable_password()
        if hasattr(user, "role"):
            user.role = "SimpleUsers"
        self._apply_names(user, claims)
        user.save()
        logger.info("SSO : compte Modoboa créé pour %s", email)
        return user

    def update_user(self, user, claims):
        """Synchronise nom/prénom depuis Keycloak à chaque connexion."""
        changed = self._apply_names(user, claims)
        if not user.is_active:
            # Un compte désactivé côté Modoboa ne doit pas pouvoir se connecter.
            raise SuspiciousOperation(
                f"Compte Modoboa désactivé pour {user.email} — connexion SSO refusée."
            )
        if changed:
            user.save(update_fields=["first_name", "last_name"])
        logger.info("SSO : connexion de %s", user.email)
        return user

    @staticmethod
    def _apply_names(user, claims):
        first = claims.get("given_name") or ""
        last = claims.get("family_name") or ""
        changed = False
        if first and user.first_name != first:
            user.first_name = first
            changed = True
        if last and user.last_name != last:
            user.last_name = last
            changed = True
        return changed
