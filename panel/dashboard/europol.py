"""
Europol incident report generator.
Produces self-contained HTML reports for law enforcement submission.
"""
import re
from datetime import datetime

from . import parsers


def generate_report(incident_ids, reporter_name='', reporter_email='',
                    organization='Securizar', jurisdiction='España - UE',
                    notes=''):
    """Generate a full Europol report dict from selected incidents."""
    registry = parsers.parse_registry()
    registry_map = {t['canary_id']: t for t in registry}
    all_alerts = parsers.parse_alerts()

    incidents_data = []
    all_iocs = {
        'ips': set(),
        'processes': set(),
        'users': set(),
        'hashes': set(),
    }
    affected_tokens = set()
    timeline_events = []

    for inc_id in incident_ids:
        inc = parsers.parse_incident(inc_id)
        if not inc:
            continue
        incidents_data.append(inc)

        meta = inc.get('metadata', {})
        canary_id = meta.get('canary_id', '')
        if canary_id:
            affected_tokens.add(canary_id)

        # Extract IOCs from evidence files
        files = inc.get('files', {})

        # SSH origins from users-sessions.txt
        sessions = files.get('users-sessions.txt', '')
        for ip_match in re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', sessions):
            if not ip_match.startswith('127.') and not ip_match.startswith('0.'):
                all_iocs['ips'].add(ip_match)

        # IPs from network connections
        netconn = files.get('network-connections.txt', '')
        for ip_match in re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', netconn):
            if not ip_match.startswith('127.') and not ip_match.startswith('0.'):
                all_iocs['ips'].add(ip_match)

        # Processes from lsof
        lsof = files.get('lsof-file.txt', '')
        for line in lsof.splitlines():
            parts = line.split()
            if len(parts) > 1 and parts[0] != 'COMMAND':
                all_iocs['processes'].add(parts[0])

        # Hashes
        hashfile = files.get('file-hash-sha256.txt', '')
        for line in hashfile.splitlines():
            h_match = re.match(r'([a-f0-9]{64})', line)
            if h_match:
                all_iocs['hashes'].add(h_match.group(1))

        # Active users
        for line in sessions.splitlines():
            parts = line.split()
            if parts:
                all_iocs['users'].add(parts[0])

        # Timeline
        ts = meta.get('timestamp_iso', meta.get('time', ''))
        timeline_events.append({
            'time': ts,
            'event': meta.get('event', 'UNKNOWN'),
            'canary_id': canary_id,
            'file': meta.get('file_accessed', ''),
            'incident_id': inc_id,
        })

        # Integrity verification
        inc['integrity'] = parsers.verify_integrity(inc_id)

    # Related alerts for affected tokens
    token_alerts = [a for a in all_alerts if a['canary_id'] in affected_tokens]
    for a in token_alerts:
        timeline_events.append({
            'time': a['timestamp_str'],
            'event': a['event'],
            'canary_id': a['canary_id'],
            'file': a['filepath'],
            'incident_id': '',
        })

    timeline_events.sort(key=lambda x: x['time'])

    # Token details
    token_details = []
    for cid in affected_tokens:
        t = registry_map.get(cid, {})
        token_details.append({
            'canary_id': cid,
            'path': t.get('path', 'N/A'),
            'type': t.get('type', 'N/A'),
            'created': t.get('created', 'N/A'),
            'desc': t.get('desc', ''),
            'alert_count': sum(1 for a in all_alerts if a['canary_id'] == cid),
        })

    case_ref = f"SEC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    return {
        'case_ref': case_ref,
        'generated_at': datetime.now().isoformat(),
        'reporter_name': reporter_name,
        'reporter_email': reporter_email,
        'organization': organization,
        'jurisdiction': jurisdiction,
        'notes': notes,
        'incidents': incidents_data,
        'timeline': timeline_events,
        'iocs': {k: sorted(v) for k, v in all_iocs.items()},
        'affected_tokens': token_details,
        'total_incidents': len(incidents_data),
        'total_alerts': len(token_alerts),
    }
