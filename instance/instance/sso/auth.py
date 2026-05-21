"""
Backend d'authentification OpenID Connect — fédération vers Keycloak.

Le token pilote l'autorisation Modoboa :
  • domaine principal    — domaine de l'e-mail (rattachement de la boîte) ;
  • rôle                 — rôles client `modoboa` du token (domainadmin /
                           superadmin → DomainAdmins / SuperAdmins ;
                           sinon SimpleUsers) ;
  • domaines administrés — attribut multivalué SSO_DOMAINS_CLAIM (cumulés au
                           domaine principal pour un DomainAdmin).

Avec SSO_PROVISION=true, un compte (et sa boîte) inconnu est créé à la volée
dans le domaine de son e-mail ; sinon le SSO ne fait que relier un compte
Modoboa existant. La connexion accepte aussi une adresse alias.
"""
import logging

from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.db import transaction

from mozilla_django_oidc.auth import OIDCAuthenticationBackend

logger = logging.getLogger("instance.sso")


class KeycloakOIDCBackend(OIDCAuthenticationBackend):
    """Relie / provisionne un compte Modoboa (`core.User`) depuis Keycloak."""

    # ── Lecture du token ───────────────────────────────────────────────────
    @staticmethod
    def _token_roles(claims) -> set:
        """Tous les rôles présents dans le token (realm + clients + `roles`)."""
        roles = set((claims.get("realm_access") or {}).get("roles") or [])
        for client in (claims.get("resource_access") or {}).values():
            roles.update(client.get("roles") or [])
        extra = claims.get("roles")
        if isinstance(extra, str):
            roles.update(extra.replace(",", " ").split())
        elif isinstance(extra, list):
            roles.update(extra)
        return {str(r).lower() for r in roles}

    @staticmethod
    def _managed_domains(claims) -> list:
        """Domaines administrés déclarés dans l'attribut SSO_DOMAINS_CLAIM."""
        raw = claims.get(settings.SSO_DOMAINS_CLAIM)
        if isinstance(raw, str):
            raw = raw.replace(",", " ").split()
        if not isinstance(raw, (list, tuple)):
            return []
        return [str(d).strip().lower() for d in raw if str(d).strip()]

    def _resolve_role(self, claims) -> str:
        roles = self._token_roles(claims)
        if roles & {r.lower() for r in settings.SSO_SUPERADMIN_ROLES}:
            return "SuperAdmins"
        if roles & {r.lower() for r in settings.SSO_DOMAINADMIN_ROLES}:
            return "DomainAdmins"
        return "SimpleUsers"

    # ── Modèles Modoboa ────────────────────────────────────────────────────
    @staticmethod
    def _get_domain(name, create):
        from modoboa.admin.models import Domain

        domain = Domain.objects.filter(name__iexact=name).first()
        if domain or not create:
            return domain
        domain = Domain(name=name.lower(), enabled=True, type="domain")
        domain.save()
        logger.info("SSO : domaine Modoboa créé — %s", name)
        return domain

    # ── Hooks mozilla-django-oidc ──────────────────────────────────────────
    def verify_claims(self, claims):
        """Un e-mail est indispensable pour rattacher / créer le compte."""
        return bool(claims.get("email"))

    def filter_users_by_claims(self, claims):
        """Retrouve le compte par e-mail, identifiant, ou adresse alias."""
        email = (claims.get("email") or "").strip().lower()
        if not email:
            return self.UserModel.objects.none()
        qs = self.UserModel.objects.filter(email__iexact=email) | \
            self.UserModel.objects.filter(username__iexact=email)
        if qs.exists():
            return qs
        # L'e-mail est peut-être une adresse alias → on remonte à la boîte.
        from modoboa.admin.models import Alias

        alias = Alias.objects.filter(address__iexact=email, internal=False).first()
        if alias:
            ar = (alias.aliasrecipient_set.filter(r_mailbox__isnull=False)
                  .select_related("r_mailbox").first())
            if ar and ar.r_mailbox and ar.r_mailbox.user_id:
                return self.UserModel.objects.filter(pk=ar.r_mailbox.user_id)
        return self.UserModel.objects.none()

    def create_user(self, claims):
        """Crée le compte + sa boîte dans le domaine de l'e-mail (SSO_PROVISION)."""
        from modoboa.admin.models import Mailbox

        email = (claims.get("email") or "").strip().lower()
        local, _, dname = email.partition("@")
        if not local or not dname:
            raise SuspiciousOperation(f"E-mail SSO invalide : {email!r}")
        with transaction.atomic():
            domain = self._get_domain(dname, create=settings.SSO_PROVISION)
            if not domain:
                raise SuspiciousOperation(
                    f"Domaine {dname} inconnu de Modoboa — connexion SSO refusée."
                )
            user = self.UserModel(username=email, email=email)
            user.set_unusable_password()
            self._apply_names(user, claims)
            user.save()
            mailbox = Mailbox(address=local, domain=domain, user=user)
            mailbox.set_quota(override_rules=True)
            mailbox.save()
            self._sync_authz(user, claims, domain)
        logger.info("SSO : compte + boîte créés pour %s (domaine %s)", email, dname)
        return user

    def update_user(self, user, claims):
        """Resynchronise nom, rôle et domaines administrés à chaque connexion."""
        if not user.is_active:
            raise SuspiciousOperation(
                f"Compte Modoboa désactivé pour {user.email} — connexion refusée."
            )
        changed = self._apply_names(user, claims)
        mailbox = getattr(user, "mailbox", None)
        primary = mailbox.domain if mailbox else self._get_domain(
            (user.email or "").partition("@")[2], create=False
        )
        self._sync_authz(user, claims, primary)
        if changed:
            user.save(update_fields=["first_name", "last_name"])
        logger.info("SSO : connexion de %s (rôle %s)", user.email, user.role)
        return user

    # ── Autorisation ───────────────────────────────────────────────────────
    def _sync_authz(self, user, claims, primary_domain):
        """Applique rôle Modoboa + rattachement aux domaines administrés."""
        role = self._resolve_role(claims)
        if user.role != role:
            user.role = role
            logger.info("SSO : %s → rôle %s", user.email, role)
        if role != "DomainAdmins":
            return
        # DomainAdmin : domaine principal + domaines de l'attribut token.
        names = set(self._managed_domains(claims))
        if primary_domain:
            names.add(primary_domain.name.lower())
        for name in names:
            domain = self._get_domain(name, create=settings.SSO_PROVISION)
            if not domain:
                logger.warning("SSO : domaine administré %s introuvable", name)
                continue
            if user not in domain.admins:
                try:
                    domain.add_admin(user)
                    logger.info("SSO : %s administrateur de %s", user.email, name)
                except Exception as exc:  # limites, etc. — non bloquant
                    logger.warning("SSO : add_admin(%s) échoué : %s", name, exc)

    @staticmethod
    def _apply_names(user, claims):
        first = claims.get("given_name") or ""
        last = claims.get("family_name") or ""
        changed = False
        if first and user.first_name != first:
            user.first_name, changed = first, True
        if last and user.last_name != last:
            user.last_name, changed = last, True
        return changed
