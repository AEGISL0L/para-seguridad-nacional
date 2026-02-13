"""
Interface with honey-monitor.sh via subprocess.
"""
import os
import re
import subprocess

from django.conf import settings

CFG = settings.DECEPTION_CONFIG


def _run_monitor(args, timeout=10):
    """Run honey-monitor.sh with given arguments."""
    script = CFG['MONITOR_SCRIPT']
    if not os.path.isfile(script):
        return False, f'Script no encontrado: {script}'
    try:
        result = subprocess.run(
            ['bash', script] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, 'Timeout ejecutando monitor'
    except OSError as e:
        return False, str(e)


def get_monitor_status():
    """Execute honey-monitor.sh status, parse output."""
    ok, output = _run_monitor(['status'])
    status = {
        'active': False,
        'pid': None,
        'tokens': 0,
        'alerts': 0,
        'last_alert': '',
        'incidents': 0,
        'auditd': 'UNKNOWN',
        'auditd_rules': 0,
        'raw': output,
    }

    for line in output.splitlines():
        line = line.strip()
        m = re.match(r'Monitor:\s*(ACTIVE|INACTIVE|STOPPED)', line, re.IGNORECASE)
        if m:
            status['active'] = m.group(1).upper() == 'ACTIVE'
            pid_m = re.search(r'PID\s+(\d+)', line)
            if pid_m:
                status['pid'] = int(pid_m.group(1))
            continue
        m = re.match(r'Tokens:\s*(\d+)', line)
        if m:
            status['tokens'] = int(m.group(1))
            continue
        m = re.match(r'Alert(?:a)?s:\s*(\d+)', line)
        if m:
            status['alerts'] = int(m.group(1))
            continue
        if line.lower().startswith('ultima:') or line.lower().startswith('última:'):
            status['last_alert'] = line.split(':', 1)[1].strip()
            continue
        m = re.match(r'Incidentes\s+forenses:\s*(\d+)', line)
        if m:
            status['incidents'] = int(m.group(1))
            continue
        m = re.match(r'Auditd:\s*(ACTIVE|INACTIVE)', line, re.IGNORECASE)
        if m:
            status['auditd'] = m.group(1).upper()
            rules_m = re.search(r'(\d+)\s+regla', line)
            if rules_m:
                status['auditd_rules'] = int(rules_m.group(1))
            continue

    # Fallback: check PID file
    if not status['active']:
        pid_file = CFG['WATCH_PID']
        if os.path.isfile(pid_file):
            try:
                pid = int(open(pid_file).read().strip())
                # Check if process is running
                os.kill(pid, 0)
                status['active'] = True
                status['pid'] = pid
            except (ValueError, OSError):
                pass

    return status


def start_monitor():
    """Execute honey-monitor.sh watchd."""
    return _run_monitor(['watchd'], timeout=15)


def stop_monitor():
    """Execute honey-monitor.sh stop."""
    return _run_monitor(['stop'])


def check_integrity():
    """Execute honey-monitor.sh check, parse output."""
    ok, output = _run_monitor(['check'], timeout=30)
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('='):
            continue
        # Parse lines like: [OK] /path/to/file  or  [ALERT] /path/to/file
        m = re.match(r'\[(\w+)\]\s+(.+)', line)
        if m:
            results.append({'status': m.group(1), 'detail': m.group(2)})
        else:
            results.append({'status': 'INFO', 'detail': line})
    return results


def get_auditd_status():
    """Check auditd rules for honey tokens."""
    try:
        result = subprocess.run(
            ['auditctl', '-l'],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.splitlines()
        honey_rules = [l for l in lines if 'honey' in l.lower()]
        return {
            'active': result.returncode == 0,
            'total_rules': len(lines),
            'honey_rules': len(honey_rules),
            'rules': honey_rules[:20],
        }
    except (OSError, subprocess.TimeoutExpired):
        return {
            'active': False,
            'total_rules': 0,
            'honey_rules': 0,
            'rules': [],
        }


def tail_alerts(n=50):
    """Read last N lines of the alert log."""
    from .parsers import parse_alerts
    alerts = parse_alerts()
    return alerts[-n:]
