"""Vues propres à l'instance de production."""
import os

from django.conf import settings
from django.http import FileResponse, JsonResponse


def spa_config(request):
    """
    Sert `config.json` consommé au démarrage par la SPA Vue.

    Le fichier est généré par la commande `load_initial_data` de Modoboa (il
    contient notamment le client_id OAuth2 du frontend, dynamique). Le reverse
    proxy frontal y mappe la route `/config.json`.
    """
    path = os.path.join(settings.BASE_DIR, "frontend", "config.json")
    if os.path.isfile(path):
        return FileResponse(open(path, "rb"), content_type="application/json")
    return JsonResponse(
        {"detail": "config.json absent — exécuter load_initial_data."}, status=503
    )
