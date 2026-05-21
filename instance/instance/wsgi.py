"""Point d'entrée WSGI de l'instance Modoboa de production."""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "instance.settings")

application = get_wsgi_application()
