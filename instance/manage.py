#!/usr/bin/env python3
"""Utilitaire de gestion Django de l'instance Modoboa de production."""
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "instance.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
