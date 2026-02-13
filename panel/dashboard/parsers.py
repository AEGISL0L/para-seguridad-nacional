"""
Parsers for deception system flat files.
Reads honey-registry.conf, honey-alerts.log, honey-forensic.log,
evidence directories, and integrity manifests.
"""
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from django.conf import settings

CFG = settings.DECEPTION_CONFIG


def parse_registry(path=None):
    """Parse honey-registry.conf → list of token dicts."""
    path = path or CFG['REGISTRY_PATH']
    tokens = []
    if not os.path.isfile(path):
        return tokens
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('|')
            if len(parts) >= 5:
                tokens.append({
                    'canary_id': parts[0],
                    'path': parts[1],
                    'type': parts[2],
                    'created': parts[3],
                    'desc': parts[4],
                })
            elif len(parts) >= 4:
                tokens.append({
                    'canary_id': parts[0],
                    'path': parts[1],
                    'type': parts[2],
                    'created': parts[3],
                    'desc': '',
                })
    return tokens


def parse_alerts(path=None, since=None):
    """Parse honey-alerts.log → list of alert dicts.
    Format: [2026-02-13T18:52:19] ACTION CANARY_ID FILE_PATH
    """
    path = path or CFG['ALERT_LOG']
    alerts = []
    if not os.path.isfile(path):
        return alerts
    pattern = re.compile(
        r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\]\s+'
        r'(\S+)\s+'
        r'(\S+)\s+'
        r'(.+)$'
    )
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            m = pattern.match(line)
            if not m:
                continue
            ts_str, event, canary_id, filepath = m.groups()
            try:
                ts = datetime.fromisoformat(ts_str)
            except ValueError:
                continue
            if since and ts < since:
                continue
            alerts.append({
                'timestamp': ts,
                'timestamp_str': ts_str,
                'event': event.upper(),
                'canary_id': canary_id,
                'filepath': filepath,
            })
    return alerts


def parse_forensic_log(path=None):
    """Parse honey-forensic.log → list of incident summary dicts."""
    path = path or CFG['FORENSIC_LOG']
    incidents = []
    if not os.path.isfile(path):
        return incidents
    current = {}
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if line.startswith('=' * 10):
                if current.get('incident_id'):
                    incidents.append(current)
                current = {}
                continue
            if ':' in line:
                key, _, val = line.partition(':')
                key = key.strip().lower().replace(' ', '_')
                val = val.strip()
                if key == 'incident':
                    current['incident_id'] = val
                elif key == 'time':
                    current['time'] = val
                    try:
                        current['timestamp'] = datetime.fromisoformat(val)
                    except ValueError:
                        current['timestamp'] = None
                elif key == 'event':
                    current['event'] = val
                elif key == 'token':
                    # "ENV-20260213-4a7c06e2 (env-prod)"
                    m = re.match(r'(\S+)\s*\(([^)]+)\)', val)
                    if m:
                        current['canary_id'] = m.group(1)
                        current['token_type'] = m.group(2)
                    else:
                        current['canary_id'] = val
                        current['token_type'] = ''
                elif key == 'file':
                    current['file'] = val
                elif key == 'evidence':
                    current['evidence_dir'] = val
                elif key == 'ssh_origins':
                    current['ssh_origins'] = val
                elif key == 'accessor':
                    current['accessor'] = val
                elif key == 'active_users':
                    current['active_users'] = val
    if current.get('incident_id'):
        incidents.append(current)
    return incidents


def parse_incident(incident_id, evidence_dir=None):
    """Parse a single evidence directory → full incident dict."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    inc_dir = os.path.join(evidence_dir, incident_id)
    if not os.path.isdir(inc_dir):
        return None

    result = {'incident_id': incident_id, 'dir': inc_dir, 'files': {}}

    # Read incident.json
    json_path = os.path.join(inc_dir, 'incident.json')
    if os.path.isfile(json_path):
        try:
            with open(json_path, encoding='utf-8') as f:
                result['metadata'] = json.load(f)
        except (json.JSONDecodeError, OSError):
            result['metadata'] = {}
    else:
        result['metadata'] = {}

    # Read all text files
    for fname in sorted(os.listdir(inc_dir)):
        fpath = os.path.join(inc_dir, fname)
        if not os.path.isfile(fpath):
            continue
        if fname == 'incident.json':
            continue
        try:
            with open(fpath, encoding='utf-8', errors='replace') as f:
                result['files'][fname] = f.read()
        except OSError:
            result['files'][fname] = '[Error reading file]'

    return result


def list_incidents(evidence_dir=None):
    """List all incident directories with basic metadata."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    if not os.path.isdir(evidence_dir):
        return []
    incidents = []
    for name in sorted(os.listdir(evidence_dir), reverse=True):
        inc_dir = os.path.join(evidence_dir, name)
        if not os.path.isdir(inc_dir):
            continue
        entry = {'incident_id': name, 'dir': inc_dir}
        json_path = os.path.join(inc_dir, 'incident.json')
        if os.path.isfile(json_path):
            try:
                with open(json_path, encoding='utf-8') as f:
                    entry['metadata'] = json.load(f)
            except (json.JSONDecodeError, OSError):
                entry['metadata'] = {}
        else:
            entry['metadata'] = {}
        # Count evidence files
        entry['file_count'] = len([
            f for f in os.listdir(inc_dir) if os.path.isfile(os.path.join(inc_dir, f))
        ])
        incidents.append(entry)
    return incidents


def parse_integrity_manifest(incident_id, evidence_dir=None):
    """Parse INTEGRITY-MANIFEST.sha256 → list of {hash, file}."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    manifest_path = os.path.join(evidence_dir, incident_id, 'INTEGRITY-MANIFEST.sha256')
    entries = []
    if not os.path.isfile(manifest_path):
        return entries
    with open(manifest_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Format: hash  filename  or  hash *filename
            parts = line.split(None, 1)
            if len(parts) == 2:
                entries.append({
                    'hash': parts[0],
                    'file': parts[1].lstrip('*'),
                })
    return entries


def verify_integrity(incident_id, evidence_dir=None):
    """Recompute hashes and compare with manifest."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    inc_dir = os.path.join(evidence_dir, incident_id)
    manifest = parse_integrity_manifest(incident_id, evidence_dir)
    results = {}
    for entry in manifest:
        fpath = os.path.join(inc_dir, entry['file'])
        if not os.path.isfile(fpath):
            results[entry['file']] = 'missing'
            continue
        h = hashlib.sha256()
        with open(fpath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        computed = h.hexdigest()
        results[entry['file']] = 'ok' if computed == entry['hash'] else 'tampered'
    return results


def get_token_status(registry=None, alerts=None):
    """Combine registry + alerts → status per token."""
    if registry is None:
        registry = parse_registry()
    if alerts is None:
        alerts = parse_alerts()

    alert_map = defaultdict(list)
    for a in alerts:
        alert_map[a['canary_id']].append(a)

    result = []
    for token in registry:
        cid = token['canary_id']
        token_alerts = alert_map.get(cid, [])
        has_delete = any(a['event'] in ('DELETE', 'DELETED') for a in token_alerts)
        has_modify = any(a['event'] in ('MODIFY', 'MODIFIED') for a in token_alerts)
        has_access = len(token_alerts) > 0

        if has_delete:
            status = 'BORRADO'
        elif has_modify:
            status = 'MODIFICADO'
        elif has_access:
            status = 'LEIDO'
        else:
            status = 'OK'

        exists = os.path.isfile(token['path'])
        result.append({
            **token,
            'status': status,
            'exists': exists,
            'alert_count': len(token_alerts),
            'last_alert': token_alerts[-1] if token_alerts else None,
        })
    return result


def get_alert_stats(alerts=None, hours=24):
    """Statistics: by type, by hour, top tokens."""
    if alerts is None:
        alerts = parse_alerts()

    cutoff = datetime.now() - timedelta(hours=hours)
    recent = [a for a in alerts if a['timestamp'] >= cutoff]

    by_type = Counter(a['event'] for a in recent)
    by_token = Counter(a['canary_id'] for a in recent)

    by_hour = defaultdict(int)
    for a in recent:
        hour_key = a['timestamp'].strftime('%Y-%m-%d %H:00')
        by_hour[hour_key] += 1

    return {
        'total': len(alerts),
        'recent': len(recent),
        'by_type': dict(by_type),
        'by_token': dict(by_token.most_common(10)),
        'by_hour': dict(sorted(by_hour.items())),
        'hours': hours,
    }


def safe_evidence_path(incident_id, filename, evidence_dir=None):
    """Validate that a file path is within the evidence directory (prevent traversal)."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    base = os.path.realpath(evidence_dir)
    target = os.path.realpath(os.path.join(base, incident_id, filename))
    if not target.startswith(base + os.sep):
        return None
    if not os.path.isfile(target):
        return None
    return target
