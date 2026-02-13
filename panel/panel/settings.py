"""
Django settings for Securizar Deception Panel.
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Generate a persistent SECRET_KEY on first run
_secret_file = BASE_DIR / '.secret_key'
if _secret_file.exists():
    SECRET_KEY = _secret_file.read_text().strip()
else:
    SECRET_KEY = secrets.token_urlsafe(50)
    _secret_file.write_text(SECRET_KEY)
    os.chmod(_secret_file, 0o600)

DEBUG = False

ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'dashboard',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'panel.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'panel.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

LANGUAGE_CODE = 'es'
TIME_ZONE = 'Europe/Madrid'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# === DECEPTION MONITOR CONFIG ===
DECEPTION_CONFIG = {
    'REGISTRY_PATH': os.path.expanduser('~/.config/securizar/honey-registry.conf'),
    'ALERT_LOG': os.path.expanduser('~/.config/securizar/honey-alerts.log'),
    'FORENSIC_LOG': os.path.expanduser('~/.config/securizar/honey-forensic.log'),
    'EVIDENCE_DIR': os.path.expanduser('~/.config/securizar/evidence'),
    'MONITOR_SCRIPT': os.path.expanduser('~/.config/securizar/honey-monitor.sh'),
    'WATCH_PID': os.path.expanduser('~/.config/securizar/honey-watch.pid'),

    'ALERT_CRITICAL_THRESHOLD': 10,
    'ALERT_WARNING_THRESHOLD': 3,
    'DEDUP_WINDOW_SECONDS': 5,

    'POLL_INTERVAL_MS': 3000,
    'MAX_ALERTS_DISPLAY': 100,
    'MAX_INCIDENTS_PAGE': 20,

    'ORGANIZATION_NAME': 'Securizar',
    'REPORTER_NAME': '',
    'REPORTER_EMAIL': '',
    'JURISDICTION': 'España - UE',

    'BIND_HOST': '127.0.0.1',
    'BIND_PORT': 3000,
}
