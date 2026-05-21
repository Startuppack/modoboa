"""
Backend d'authentification OpenID Connect — fédération vers Keycloak.

Le token pilote l'identité ET l'autorisation Modoboa. Le claim standard
`email` n'est PAS utilisé pour la boîte (c'est souvent l'e-mail perso) — la
boîte vient d'attributs Keycloak dédiés :

  • SSO_EMAIL_CLAIM (`modoboa_email`)     — adresse principale de la boîte ;
  • SSO_ALIASES_CLAIM (`modoboa_aliases`) — adresses alias (multivalué) ;
  • rôles client `modoboa`                — domainadmin/superadmin → rôle ;
  • SSO_DOMAINS_CLAIM (`modoboa_domains`) — domaines administrés (DomainAdmin).

Le claim `email` standard, s'il existe, est conservé comme e-mail secondaire
(récupération de mot de passe). Avec SSO_PROVISION=true, le compte, sa boîte
et ses alias sont créés à la première connexion — au nom du SuperAdmin
(propriété des objets requise par l'app `limits`).
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
    def _mailbox_address(claims) -> str:
        """Adresse principale de la boîte (attribut dédié, jamais `email`)."""
        return (claims.get(settings.SSO_EMAIL_CLAIM) or "").strip().lower()

    @staticmethod
    def _claim_list(claims, key) -> list:
        """Lit un claim multivalué (liste JSON ou chaîne séparée)."""
        raw = claims.get(key)
        if isinstance(raw, str):
            raw = raw.replace(",", " ").split()
        if not isinstance(raw, (list, tuple)):
            return []
        return [str(v).strip().lower() for v in raw if str(v).strip()]

    def _aliases(self, claims) -> list:
        return self._claim_list(claims, settings.SSO_ALIASES_CLAIM)

    def _managed_domains(self, claims) -> list:
        return self._claim_list(claims, settings.SSO_DOMAINS_CLAIM)

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

    def _resolve_role(self, claims) -> str:
        roles = self._token_roles(claims)
        if roles & {r.lower() for r in settings.SSO_SUPERADMIN_ROLES}:
            return "SuperAdmins"
        if roles & {r.lower() for r in settings.SSO_DOMAINADMIN_ROLES}:
            return "DomainAdmins"
        return "SimpleUsers"

    # ── Modèles Modoboa ────────────────────────────────────────────────────
    def _superadmin(self):
        """SuperAdmin propriétaire des objets provisionnés (compte `admin`)."""
        return (self.UserModel.objects.filter(is_superuser=True)
                .order_by("pk").first())

    @staticmethod
    def _get_domain(name, create, creator=None):
        from modoboa.admin.models import Domain

        if not name:
            return None
        domain = Domain.objects.filter(name__iexact=name).first()
        if domain or not create:
            return domain
        domain = Domain(name=name.lower(), enabled=True, type="domain")
        domain.save(creator=creator)
        logger.info("SSO : domaine Modoboa créé — %s", name)
        return domain

    # ── Hooks mozilla-django-oidc ──────────────────────────────────────────
    def verify_claims(self, claims):
        """L'adresse de boîte dédiée est indispensable au rattachement."""
        if not self._mailbox_address(claims):
            logger.warning("SSO : token sans attribut %s — refusé",
                            settings.SSO_EMAIL_CLAIM)
            return False
        return True

    def filter_users_by_claims(self, claims):
        """Retrouve le compte par son adresse de boîte, ou une de ses alias."""
        address = self._mailbox_address(claims)
        if not address:
            return self.UserModel.objects.none()
        qs = self.UserModel.objects.filter(username__iexact=address) | \
            self.UserModel.objects.filter(email__iexact=address)
        if qs.exists():
            return qs
        # L'adresse correspond peut-être à un alias → on remonte à la boîte.
        from modoboa.admin.models import Alias

        for addr in [address] + self._aliases(claims):
            alias = Alias.objects.filter(address__iexact=addr, internal=False).first()
            if not alias:
                continue
            ar = (alias.aliasrecipient_set.filter(r_mailbox__isnull=False)
                  .select_related("r_mailbox").first())
            if ar and ar.r_mailbox and ar.r_mailbox.user_id:
                return self.UserModel.objects.filter(pk=ar.r_mailbox.user_id)
        return self.UserModel.objects.none()

    def create_user(self, claims):
        """Crée le compte + sa boîte + ses alias (SSO_PROVISION)."""
        from modoboa.admin.models import Mailbox
        from modoboa.lib.permissions import grant_access_to_object

        address = self._mailbox_address(claims)
        local, _, dname = address.partition("@")
        if not local or not dname:
            raise SuspiciousOperation(f"Adresse de boîte SSO invalide : {address!r}")
        creator = self._superadmin()
        with transaction.atomic():
            domain = self._get_domain(dname, create=settings.SSO_PROVISION,
                                      creator=creator)
            if not domain:
                raise SuspiciousOperation(
                    f"Domaine {dname} inconnu de Modoboa — connexion SSO refusée."
                )
            user = self.UserModel(username=address, email=address)
            user.set_unusable_password()
            self._apply_profile(user, claims)
            user.save()
            if creator:
                grant_access_to_object(creator, user, is_owner=True)
            mailbox = Mailbox(address=local, domain=domain, user=user)
            mailbox.set_quota(override_rules=True)
            mailbox.save(creator=creator)
            self._sync_aliases(user, mailbox, claims, creator)
            self._sync_authz(user, claims, domain, creator)
        logger.info("SSO : compte + boîte créés — %s (domaine %s)", address, dname)
        return user

    def update_user(self, user, claims):
        """Resynchronise profil, alias, rôle et domaines à chaque connexion."""
        if not user.is_active:
            raise SuspiciousOperation(
                f"Compte Modoboa désactivé pour {user.username} — connexion refusée."
            )
        creator = self._superadmin()
        with transaction.atomic():
            changed = self._apply_profile(user, claims)
            if changed:
                user.save()
            mailbox = getattr(user, "mailbox", None)
            primary = mailbox.domain if mailbox else self._get_domain(
                self._mailbox_address(claims).partition("@")[2], create=False
            )
            if mailbox:
                self._sync_aliases(user, mailbox, claims, creator)
            self._sync_authz(user, claims, primary, creator)
        logger.info("SSO : connexion de %s (rôle %s)", user.username, user.role)
        return user

    # ── Profil / alias / autorisation ──────────────────────────────────────
    @staticmethod
    def _apply_profile(user, claims):
        """Synchronise nom/prénom + e-mail secondaire (= e-mail perso du token)."""
        changed = False
        for field, value in (("first_name", claims.get("given_name")),
                              ("last_name", claims.get("family_name"))):
            value = value or ""
            if value and getattr(user, field) != value:
                setattr(user, field, value)
                changed = True
        # Le claim `email` standard = e-mail perso → e-mail secondaire Modoboa.
        personal = (claims.get("email") or "").strip().lower()
        if personal and hasattr(user, "secondary_email") and \
                user.secondary_email != personal:
            user.secondary_email = personal
            changed = True
        return changed

    def _sync_aliases(self, user, mailbox, claims, creator):
        """Crée/relie les adresses alias de la boîte (additif, non destructif)."""
        from modoboa.admin.models import Alias

        recipient = f"{mailbox.address}@{mailbox.domain.name}"
        for addr in self._aliases(claims):
            if addr == recipient:
                continue
            alocal, _, adomain = addr.partition("@")
            if not alocal or not adomain:
                continue
            domain = self._get_domain(adomain, create=settings.SSO_PROVISION,
                                      creator=creator)
            if not domain:
                logger.warning("SSO : domaine d'alias %s introuvable", adomain)
                continue
            try:
                alias = Alias.objects.filter(address__iexact=addr).first()
                if not alias:
                    alias = Alias(address=addr, domain=domain, enabled=True,
                                  internal=False)
                    alias.save(creator=creator)
                alias.set_recipients([recipient])
                logger.info("SSO : alias %s → %s", addr, recipient)
            except Exception as exc:  # non bloquant
                logger.warning("SSO : alias %s échoué : %s", addr, exc)

    def _sync_authz(self, user, claims, primary_domain, creator):
        """Applique rôle Modoboa + rattachement aux domaines administrés."""
        role = self._resolve_role(claims)
        if user.role != role:
            user.role = role
            logger.info("SSO : %s → rôle %s", user.username, role)
        if role != "DomainAdmins":
            return
        names = set(self._managed_domains(claims))
        if primary_domain:
            names.add(primary_domain.name.lower())
        for name in names:
            domain = self._get_domain(name, create=settings.SSO_PROVISION,
                                      creator=creator)
            if not domain:
                logger.warning("SSO : domaine administré %s introuvable", name)
                continue
            if user not in domain.admins:
                try:
                    domain.add_admin(user)
                    logger.info("SSO : %s administrateur de %s", user.username, name)
                except Exception as exc:  # limites, etc. — non bloquant
                    logger.warning("SSO : add_admin(%s) échoué : %s", name, exc)
