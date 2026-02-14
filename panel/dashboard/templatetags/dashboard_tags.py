"""Custom template filters for the deception dashboard."""
from django import template

register = template.Library()


@register.filter
def event_color(event):
    """Return Tailwind color class for alert event type."""
    colors = {
        'DELETE': 'text-red-400',
        'DELETED': 'text-red-400',
        'MODIFY': 'text-yellow-400',
        'MODIFIED': 'text-yellow-400',
        'OPEN': 'text-blue-400',
        'ACCESS': 'text-sky-400',
    }
    return colors.get(str(event).upper(), 'text-gray-400')


@register.filter
def event_bg(event):
    """Return Tailwind bg class for alert event type."""
    colors = {
        'DELETE': 'bg-red-900/30 border-red-700',
        'DELETED': 'bg-red-900/30 border-red-700',
        'MODIFY': 'bg-yellow-900/30 border-yellow-700',
        'MODIFIED': 'bg-yellow-900/30 border-yellow-700',
        'OPEN': 'bg-blue-900/30 border-blue-700',
        'ACCESS': 'bg-sky-900/30 border-sky-700',
    }
    return colors.get(str(event).upper(), 'bg-gray-800 border-gray-700')


@register.filter
def status_color(status):
    """Return Tailwind classes for token status."""
    colors = {
        'OK': 'text-green-400 bg-green-900/30',
        'LEIDO': 'text-yellow-400 bg-yellow-900/30',
        'MODIFICADO': 'text-orange-400 bg-orange-900/30',
        'BORRADO': 'text-red-400 bg-red-900/30',
    }
    return colors.get(str(status).upper(), 'text-gray-400 bg-gray-800')


@register.filter
def integrity_color(status):
    """Return Tailwind class for integrity status."""
    if status == 'ok':
        return 'text-green-400'
    if status == 'tampered':
        return 'text-red-400'
    return 'text-yellow-400'


@register.filter
def short_path(path, max_len=50):
    """Shorten a file path for display."""
    path = str(path)
    if len(path) <= max_len:
        return path
    return '...' + path[-(max_len - 3):]


@register.filter
def short_hash(h, length=12):
    """Show first N chars of a hash."""
    return str(h)[:length]


@register.filter
def token_type_icon(token_type):
    """Return an emoji-free text indicator for token type."""
    icons = {
        'aws-creds': 'AWS',
        'ssh-key': 'SSH',
        'docker-auth': 'DCK',
        'k8s-config': 'K8S',
        'db-creds': 'DB',
        'net-creds': 'NET',
        'cloud-storage': 'CLD',
        'github-auth': 'GIT',
        'terraform': 'TF',
        'vpn-config': 'VPN',
        'npm-auth': 'NPM',
        'env-prod': 'ENV',
        'password-export': 'PWD',
        'crypto-seed': 'BTC',
        'financial': 'FIN',
    }
    return icons.get(str(token_type), token_type[:3].upper())


@register.filter
def threat_color(level):
    """Return badge class for threat level."""
    colors = {
        'CRITICAL': 'badge-red',
        'HIGH': 'badge-orange',
        'MEDIUM': 'badge-yellow',
        'LOW': 'badge-blue',
        'INFO': 'badge-green',
    }
    return colors.get(str(level).upper(), 'badge-blue')


@register.filter
def threat_text_color(level):
    """Return text color class for threat level."""
    colors = {
        'CRITICAL': 'text-red',
        'HIGH': 'text-yellow',
        'MEDIUM': 'text-yellow',
        'LOW': 'text-blue',
        'INFO': 'text-green',
    }
    return colors.get(str(level).upper(), 'text-muted')


@register.filter
def tactic_color(tactic):
    """Return CSS color for ATT&CK tactic."""
    colors = {
        'Initial Access': '#f85149',
        'Execution': '#d29922',
        'Credential Access': '#d18616',
        'Discovery': '#58a6ff',
        'Lateral Movement': '#bc8cff',
        'Collection': '#39d2c0',
        'Exfiltration': '#f85149',
        'Impact': '#f85149',
        'Defense Evasion': '#d29922',
    }
    return colors.get(str(tactic), '#8b949e')
