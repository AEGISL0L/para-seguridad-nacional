"""
Parsers for deception system flat files.
Reads honey-registry.conf, honey-alerts.log, honey-forensic.log,
evidence directories, and integrity manifests.
"""
import hashlib
import json
import math
import os
import re
import statistics
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


def extract_accessor(incident_id, evidence_dir=None):
    """Extract process accessor info from lsof-file.txt evidence.
    Returns dict with pid, user, cmd if found."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    lsof_path = os.path.join(evidence_dir, incident_id, 'lsof-file.txt')
    if not os.path.isfile(lsof_path):
        return None
    accessor = {'pid': None, 'user': None, 'cmd': None, 'source': None}
    try:
        with open(lsof_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
        # Try /proc fd scan format: PID=1234 USER=juav CMD=cat /path
        for line in content.splitlines():
            m = re.match(r'PID=(\d+)\s+USER=(\S+)\s+CMD=(.*)', line)
            if m:
                accessor['pid'] = m.group(1)
                accessor['user'] = m.group(2)
                accessor['cmd'] = m.group(3).strip()
                accessor['source'] = 'proc_scan'
                return accessor
        # Try lsof table format (COMMAND PID USER ...)
        for line in content.splitlines():
            if line.startswith('COMMAND') or 'no open handles' in line:
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[1].isdigit():
                accessor['cmd'] = parts[0]
                accessor['pid'] = parts[1]
                accessor['user'] = parts[2]
                accessor['source'] = 'lsof'
                return accessor
    except OSError:
        pass
    return None


def correlate_incidents(evidence_dir=None):
    """Group incidents by canary_id and detect patterns.
    Returns dict with correlation analysis."""
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return {'groups': {}, 'feedback_loops': [], 'unique_tokens': 0}

    groups = defaultdict(list)
    for inc in incidents:
        cid = inc.get('metadata', {}).get('canary_id', 'UNKNOWN')
        groups[cid].append(inc)

    # Detect feedback loops: >5 incidents for same token within 5 min
    feedback_loops = []
    for cid, incs in groups.items():
        if len(incs) < 5:
            continue
        timestamps = []
        for i in incs:
            ts_str = i.get('metadata', {}).get('timestamp_iso', '')
            try:
                timestamps.append(datetime.fromisoformat(ts_str.replace('Z', '+00:00')))
            except (ValueError, AttributeError):
                pass
        if len(timestamps) >= 5:
            timestamps.sort()
            # Check if 5+ events within 5 minutes
            for j in range(len(timestamps) - 4):
                if (timestamps[j + 4] - timestamps[j]).total_seconds() < 300:
                    feedback_loops.append({
                        'canary_id': cid,
                        'count': len(incs),
                        'window_start': timestamps[j].isoformat(),
                        'window_end': timestamps[j + 4].isoformat(),
                    })
                    break

    # Build unique accessors
    accessors = set()
    for inc in incidents:
        acc = extract_accessor(inc['incident_id'], evidence_dir)
        if acc and acc.get('pid'):
            accessors.add(f"{acc['user']}:{acc['cmd']}")

    return {
        'groups': {cid: len(incs) for cid, incs in groups.items()},
        'feedback_loops': feedback_loops,
        'unique_tokens': len(groups),
        'unique_accessors': list(accessors),
        'total_incidents': len(incidents),
    }


def get_alert_dedup_stats(alerts=None):
    """Calculate dedup stats: unique events vs total (feedback loop detection)."""
    if alerts is None:
        alerts = parse_alerts()
    if not alerts:
        return {'total': 0, 'unique': 0, 'dedup_ratio': 0.0}

    # Unique = 1 per (canary_id, 60-second window)
    seen = set()
    unique = 0
    for a in alerts:
        ts = a['timestamp']
        # Round to 60-second windows
        window = ts.replace(second=0, microsecond=0)
        key = (a['canary_id'], window)
        if key not in seen:
            seen.add(key)
            unique += 1

    ratio = (1 - unique / len(alerts)) * 100 if alerts else 0
    return {
        'total': len(alerts),
        'unique': unique,
        'dedup_ratio': round(ratio, 1),
    }


def extract_iocs(incident_id, evidence_dir=None):
    """Extract Indicators of Compromise from all evidence files.
    Returns dict with ips, processes, users, ssh_origins, hashes, network."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    inc_dir = os.path.join(evidence_dir, incident_id)
    if not os.path.isdir(inc_dir):
        return {}

    iocs = {
        'external_ips': [],
        'ssh_origins': [],
        'processes_with_net': [],
        'active_users': [],
        'file_hashes': [],
        'arp_anomalies': 0,
        'listening_ports': [],
        'vpn_active': False,
        'dns_servers': [],
    }

    # --- Network connections ---
    net_path = os.path.join(inc_dir, 'network-connections.txt')
    if os.path.isfile(net_path):
        try:
            with open(net_path, encoding='utf-8', errors='replace') as f:
                content = f.read(65536)  # Limit read size
            seen_ips = set()
            # Parse ESTAB lines: extract peer IPs and process names
            for line in content.splitlines():
                # TCP established: extract peer IP and process
                m = re.search(
                    r'ESTAB\s+\d+\s+\d+\s+\S+:(\d+)\s+'
                    r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+'
                    r'(?:users:\(\("([^"]+)",pid=(\d+))?',
                    line
                )
                if m:
                    peer_ip = m.group(2)
                    peer_port = m.group(3)
                    proc_name = m.group(4) or ''
                    proc_pid = m.group(5) or ''
                    # Filter private/loopback
                    if not peer_ip.startswith(('127.', '10.', '192.168.', '0.')):
                        if peer_ip not in seen_ips:
                            seen_ips.add(peer_ip)
                            iocs['external_ips'].append({
                                'ip': peer_ip,
                                'port': peer_port,
                                'process': proc_name,
                                'pid': proc_pid,
                            })
                    if proc_name and proc_pid:
                        iocs['processes_with_net'].append({
                            'name': proc_name,
                            'pid': proc_pid,
                            'peer': f"{peer_ip}:{peer_port}",
                        })
                # SSH sessions (port 22)
                if ':22 ' in line or ':22\t' in line:
                    ssh_m = re.search(r'(\d+\.\d+\.\d+\.\d+):\d+\s', line)
                    if ssh_m:
                        ip = ssh_m.group(1)
                        if not ip.startswith('127.') and ip not in [s['ip'] for s in iocs['ssh_origins']]:
                            iocs['ssh_origins'].append({'ip': ip})
                # VPN detection
                if 'protonvpn' in line.lower() or 'wireguard' in line.lower() or 'openvpn' in line.lower():
                    iocs['vpn_active'] = True
                # Listening ports
                listen_m = re.match(
                    r'LISTEN\s+\d+\s+\d+\s+(\S+):(\d+)\s+.*?'
                    r'(?:users:\(\("([^"]+)")?',
                    line
                )
                if listen_m:
                    iocs['listening_ports'].append({
                        'addr': listen_m.group(1),
                        'port': listen_m.group(2),
                        'process': listen_m.group(3) or '',
                    })
                # DNS servers (port 853 or 53)
                if ':853 ' in line or ':53 ' in line:
                    dns_m = re.search(r'(\d+\.\d+\.\d+\.\d+):(853|53)', line)
                    if dns_m:
                        dns_ip = dns_m.group(1)
                        if dns_ip not in iocs['dns_servers']:
                            iocs['dns_servers'].append(dns_ip)
        except OSError:
            pass

    # Deduplicate processes_with_net by pid
    seen_pids = set()
    unique_procs = []
    for p in iocs['processes_with_net']:
        if p['pid'] not in seen_pids:
            seen_pids.add(p['pid'])
            unique_procs.append(p)
    iocs['processes_with_net'] = unique_procs

    # --- ARP anomalies ---
    arp_path = os.path.join(inc_dir, 'network-arp-routes.txt')
    if os.path.isfile(arp_path):
        try:
            with open(arp_path, encoding='utf-8', errors='replace') as f:
                content = f.read(32768)
            iocs['arp_anomalies'] = content.lower().count('failed')
        except OSError:
            pass

    # --- Users & sessions ---
    users_path = os.path.join(inc_dir, 'users-sessions.txt')
    if os.path.isfile(users_path):
        try:
            with open(users_path, encoding='utf-8', errors='replace') as f:
                content = f.read(16384)
            seen_users = set()
            # Only parse lines between "=== w ===" and next "==="
            in_w_section = False
            skip_header = False
            for line in content.splitlines():
                if line.strip() == '=== w ===':
                    in_w_section = True
                    skip_header = True
                    continue
                if in_w_section and line.strip().startswith('==='):
                    in_w_section = False
                    continue
                if not in_w_section:
                    continue
                if skip_header:
                    # Skip the "HH:MM up..." line and header
                    if line.strip().startswith(('USER', 'USUARIO')):
                        skip_header = False
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    uname = parts[0]
                    if uname not in seen_users and uname.isalpha() and len(uname) < 32:
                        seen_users.add(uname)
                        iocs['active_users'].append({
                            'user': uname,
                            'tty': parts[1],
                            'from': parts[2] if parts[2] != '-' else 'local',
                        })
        except OSError:
            pass

    # --- File hashes ---
    hash_path = os.path.join(inc_dir, 'file-hash-sha256.txt')
    if os.path.isfile(hash_path):
        try:
            with open(hash_path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2 and len(parts[0]) >= 64:
                        algo = 'sha512' if len(parts[0]) > 64 else 'sha256'
                        iocs['file_hashes'].append({
                            'hash': parts[0],
                            'file': parts[1].lstrip('*'),
                            'algo': algo,
                        })
        except OSError:
            pass

    return iocs


def extract_key_findings(incident_id, evidence_dir=None):
    """Distill the most important forensic findings from an incident.
    Returns list of finding dicts with severity, category, detail."""
    findings = []
    iocs = extract_iocs(incident_id, evidence_dir)
    accessor = extract_accessor(incident_id, evidence_dir)

    if not iocs:
        return findings

    # Accessor identified
    if accessor and accessor.get('pid'):
        findings.append({
            'severity': 'HIGH',
            'category': 'ACCESSOR',
            'title': 'Proceso accesor identificado',
            'detail': f"PID {accessor['pid']} ({accessor['user']}) ejecuto: {accessor['cmd']}",
        })

    # SSH sessions from external
    for ssh in iocs.get('ssh_origins', []):
        findings.append({
            'severity': 'CRITICAL',
            'category': 'SSH',
            'title': 'Sesion SSH desde IP externa',
            'detail': f"Conexion SSH origen: {ssh['ip']}",
        })

    # External IPs
    ext_ips = iocs.get('external_ips', [])
    if ext_ips:
        ip_list = ', '.join(f"{e['ip']}:{e['port']}" for e in ext_ips[:5])
        findings.append({
            'severity': 'MEDIUM',
            'category': 'NETWORK',
            'title': f'{len(ext_ips)} IPs externas con conexion activa',
            'detail': ip_list,
        })

    # ARP anomalies (potential scanning)
    arp_fails = iocs.get('arp_anomalies', 0)
    if arp_fails > 10:
        findings.append({
            'severity': 'HIGH',
            'category': 'ARP',
            'title': f'{arp_fails} entradas ARP FAILED',
            'detail': 'Numero elevado de ARP failures sugiere escaneo de red activo',
        })

    # VPN active
    if iocs.get('vpn_active'):
        findings.append({
            'severity': 'INFO',
            'category': 'VPN',
            'title': 'VPN activa durante el incidente',
            'detail': 'El trafico pasaba por VPN (ProtonVPN/WireGuard/OpenVPN detectado)',
        })

    # Multiple active users
    users = iocs.get('active_users', [])
    if len(users) > 1:
        user_list = ', '.join(u['user'] for u in users)
        findings.append({
            'severity': 'MEDIUM',
            'category': 'USERS',
            'title': f'{len(users)} usuarios activos',
            'detail': user_list,
        })

    return findings


def build_timeline(evidence_dir=None, limit=200):
    """Build unified chronological timeline from all incidents and alerts.
    Returns list sorted by timestamp."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    events = []

    # From alerts log
    alerts = parse_alerts()
    for a in alerts[-limit:]:
        events.append({
            'timestamp': a['timestamp'],
            'timestamp_str': a['timestamp_str'],
            'type': 'alert',
            'event': a['event'],
            'canary_id': a['canary_id'],
            'detail': a['filepath'],
            'incident_id': None,
        })

    # From forensic incidents
    incidents = list_incidents(evidence_dir)
    for inc in incidents[:limit]:
        meta = inc.get('metadata', {})
        ts_str = meta.get('timestamp_iso', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00').split('+')[0])
        except (ValueError, AttributeError):
            ts = None
        if ts:
            accessor = extract_accessor(inc['incident_id'], evidence_dir)
            acc_str = ''
            if accessor and accessor.get('pid'):
                acc_str = f" | Accesor: {accessor['user']} PID {accessor['pid']}"
            events.append({
                'timestamp': ts,
                'timestamp_str': ts_str,
                'type': 'forensic',
                'event': meta.get('event', '?'),
                'canary_id': meta.get('canary_id', '?'),
                'detail': f"{meta.get('file_accessed', '?')}{acc_str}",
                'incident_id': inc['incident_id'],
            })

    # Sort by timestamp descending
    events.sort(key=lambda e: e['timestamp'] if e['timestamp'] else datetime.min, reverse=True)
    return events[:limit]


# ============================================================
# MITRE ATT&CK Mapping
# ============================================================

# Token type → ATT&CK techniques triggered when accessed
MITRE_TOKEN_MAP = {
    'aws-creds': [
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
        ('T1078.004', 'Valid Accounts: Cloud Accounts'),
    ],
    'ssh-key': [
        ('T1552.004', 'Unsecured Credentials: Private Keys'),
        ('T1021.004', 'Remote Services: SSH'),
    ],
    'docker-auth': [
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
        ('T1610', 'Deploy Container'),
    ],
    'k8s-config': [
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
        ('T1609', 'Container Administration Command'),
    ],
    'db-creds': [
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
        ('T1213', 'Data from Information Repositories'),
    ],
    'net-creds': [
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
        ('T1040', 'Network Sniffing'),
    ],
    'cloud-storage': [
        ('T1530', 'Data from Cloud Storage Object'),
        ('T1537', 'Transfer Data to Cloud Account'),
    ],
    'github-auth': [
        ('T1528', 'Steal Application Access Token'),
        ('T1195.002', 'Supply Chain: Software Supply Chain'),
    ],
    'terraform': [
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
        ('T1580', 'Cloud Infrastructure Discovery'),
    ],
    'vpn-config': [
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
        ('T1133', 'External Remote Services'),
    ],
    'npm-auth': [
        ('T1528', 'Steal Application Access Token'),
        ('T1195.002', 'Supply Chain: Software Supply Chain'),
    ],
    'env-prod': [
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
        ('T1082', 'System Information Discovery'),
    ],
    'password-export': [
        ('T1555', 'Credentials from Password Stores'),
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
    ],
    'crypto-seed': [
        ('T1552.001', 'Unsecured Credentials: Credentials In Files'),
        ('T1657', 'Financial Theft'),
    ],
    'financial': [
        ('T1005', 'Data from Local System'),
        ('T1657', 'Financial Theft'),
    ],
}

# Event type → ATT&CK techniques
MITRE_EVENT_MAP = {
    'ACCESS': [('T1005', 'Data from Local System'), ('T1083', 'File and Directory Discovery')],
    'OPEN': [('T1005', 'Data from Local System'), ('T1083', 'File and Directory Discovery')],
    'MODIFY': [('T1565.001', 'Data Manipulation: Stored Data Manipulation')],
    'MODIFIED': [('T1565.001', 'Data Manipulation: Stored Data Manipulation')],
    'DELETE': [('T1485', 'Data Destruction'), ('T1070.004', 'Indicator Removal: File Deletion')],
    'DELETED': [('T1485', 'Data Destruction'), ('T1070.004', 'Indicator Removal: File Deletion')],
}

# ATT&CK tactic grouping for heatmap
MITRE_TACTIC_MAP = {
    'T1078': 'Initial Access',
    'T1078.004': 'Initial Access',
    'T1133': 'Initial Access',
    'T1195.002': 'Initial Access',
    'T1005': 'Collection',
    'T1213': 'Collection',
    'T1530': 'Collection',
    'T1040': 'Credential Access',
    'T1528': 'Credential Access',
    'T1552': 'Credential Access',
    'T1552.001': 'Credential Access',
    'T1552.004': 'Credential Access',
    'T1555': 'Credential Access',
    'T1021.004': 'Lateral Movement',
    'T1537': 'Exfiltration',
    'T1082': 'Discovery',
    'T1083': 'Discovery',
    'T1580': 'Discovery',
    'T1565.001': 'Impact',
    'T1485': 'Impact',
    'T1070.004': 'Defense Evasion',
    'T1609': 'Execution',
    'T1610': 'Execution',
    'T1657': 'Impact',
}

# Token type → base threat weight (0-10)
TOKEN_THREAT_WEIGHT = {
    'crypto-seed': 10, 'financial': 10, 'password-export': 9,
    'aws-creds': 8, 'ssh-key': 8, 'db-creds': 8,
    'k8s-config': 7, 'docker-auth': 7, 'terraform': 7,
    'vpn-config': 7, 'github-auth': 7, 'env-prod': 6,
    'cloud-storage': 6, 'npm-auth': 6, 'net-creds': 5,
}

# Event → multiplier
EVENT_MULTIPLIER = {
    'DELETE': 3.0, 'DELETED': 3.0,
    'MODIFY': 2.0, 'MODIFIED': 2.0,
    'ACCESS': 1.0, 'OPEN': 1.0,
}


def map_mitre_techniques(token_type, event):
    """Map a token access event to MITRE ATT&CK techniques.
    Returns list of (technique_id, name, tactic) tuples."""
    techniques = []
    seen = set()
    for tid, name in MITRE_TOKEN_MAP.get(token_type, []):
        if tid not in seen:
            seen.add(tid)
            tactic = MITRE_TACTIC_MAP.get(tid, 'Unknown')
            techniques.append({'id': tid, 'name': name, 'tactic': tactic})
    for tid, name in MITRE_EVENT_MAP.get(event.upper(), []):
        if tid not in seen:
            seen.add(tid)
            tactic = MITRE_TACTIC_MAP.get(tid, 'Unknown')
            techniques.append({'id': tid, 'name': name, 'tactic': tactic})
    return techniques


def compute_threat_score(incident_id, evidence_dir=None):
    """Compute a 0-100 threat score for an incident based on IOCs and context.
    Returns dict with score, breakdown, and level."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    inc = parse_incident(incident_id, evidence_dir)
    if not inc:
        return {'score': 0, 'level': 'UNKNOWN', 'breakdown': []}

    meta = inc.get('metadata', {})
    token_type = meta.get('token_type', '')
    event = meta.get('event', 'ACCESS')
    breakdown = []
    score = 0.0

    # 1. Token value (0-10) × event multiplier (1-3) → 0-30
    base_weight = TOKEN_THREAT_WEIGHT.get(token_type, 4)
    multiplier = EVENT_MULTIPLIER.get(event.upper(), 1.0)
    token_score = base_weight * multiplier
    score += token_score
    breakdown.append(f'Token {token_type} ({base_weight}) x {event} ({multiplier}x) = {token_score:.0f}')

    # 2. IOC analysis
    iocs = extract_iocs(incident_id, evidence_dir)
    accessor = extract_accessor(incident_id, evidence_dir)

    if accessor and accessor.get('pid'):
        score += 15
        breakdown.append(f'Accessor identificado: +15')

    ext_ips = iocs.get('external_ips', [])
    if ext_ips:
        ip_bonus = min(len(ext_ips) * 3, 15)
        score += ip_bonus
        breakdown.append(f'{len(ext_ips)} IPs externas: +{ip_bonus}')

    ssh_origins = iocs.get('ssh_origins', [])
    if ssh_origins:
        score += 20
        breakdown.append(f'SSH externo ({len(ssh_origins)} origenes): +20')

    arp = iocs.get('arp_anomalies', 0)
    if arp > 10:
        score += 10
        breakdown.append(f'ARP anomalias ({arp}): +10')
    elif arp > 0:
        score += 3
        breakdown.append(f'ARP anomalias ({arp}): +3')

    if not iocs.get('vpn_active'):
        score += 5
        breakdown.append('Sin VPN (exposicion directa): +5')

    users = iocs.get('active_users', [])
    if len(users) > 2:
        score += 5
        breakdown.append(f'{len(users)} usuarios activos: +5')

    # Clamp to 0-100
    score = max(0, min(100, score))

    if score >= 70:
        level = 'CRITICAL'
    elif score >= 50:
        level = 'HIGH'
    elif score >= 30:
        level = 'MEDIUM'
    elif score >= 10:
        level = 'LOW'
    else:
        level = 'INFO'

    return {'score': round(score), 'level': level, 'breakdown': breakdown}


def build_mitre_heatmap(evidence_dir=None):
    """Build MITRE ATT&CK heatmap from all incidents.
    Returns dict: tactic → {technique_id → {name, count, incidents}}."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    incidents = list_incidents(evidence_dir)

    heatmap = defaultdict(lambda: defaultdict(lambda: {'name': '', 'count': 0, 'incidents': []}))
    technique_totals = Counter()

    for inc in incidents:
        meta = inc.get('metadata', {})
        token_type = meta.get('token_type', '')
        event = meta.get('event', 'ACCESS')
        iid = inc['incident_id']

        techniques = map_mitre_techniques(token_type, event)
        for t in techniques:
            tactic = t['tactic']
            tid = t['id']
            heatmap[tactic][tid]['name'] = t['name']
            heatmap[tactic][tid]['count'] += 1
            if len(heatmap[tactic][tid]['incidents']) < 5:
                heatmap[tactic][tid]['incidents'].append(iid)
            technique_totals[tid] += 1

    # Convert to sorted structure
    result = {}
    tactic_order = [
        'Initial Access', 'Execution', 'Credential Access', 'Discovery',
        'Lateral Movement', 'Collection', 'Exfiltration', 'Impact',
        'Defense Evasion',
    ]
    for tactic in tactic_order:
        if tactic in heatmap:
            techniques = []
            for tid, data in sorted(heatmap[tactic].items(), key=lambda x: -x[1]['count']):
                techniques.append({
                    'id': tid,
                    'name': data['name'],
                    'count': data['count'],
                    'incidents': data['incidents'],
                })
            result[tactic] = techniques

    return {
        'heatmap': result,
        'total_techniques': len(technique_totals),
        'total_incidents': len(incidents),
        'top_techniques': technique_totals.most_common(10),
    }


def enrich_ip(ip_str):
    """Enrich an IP address with reverse DNS and classification.
    Uses only stdlib (no external API calls)."""
    import ipaddress
    import socket
    result = {'ip': ip_str, 'rdns': '', 'type': 'public', 'asn_hint': ''}
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_private:
            result['type'] = 'private'
        elif addr.is_loopback:
            result['type'] = 'loopback'
        elif addr.is_link_local:
            result['type'] = 'link-local'
        elif addr.is_reserved:
            result['type'] = 'reserved'
    except ValueError:
        result['type'] = 'invalid'
        return result
    try:
        rdns = socket.getfqdn(ip_str)
        if rdns != ip_str:
            result['rdns'] = rdns
            # Heuristic ASN hints from rDNS
            rdns_lower = rdns.lower()
            if 'google' in rdns_lower or 'goog' in rdns_lower:
                result['asn_hint'] = 'Google'
            elif 'amazon' in rdns_lower or 'aws' in rdns_lower:
                result['asn_hint'] = 'AWS'
            elif 'azure' in rdns_lower or 'microsoft' in rdns_lower:
                result['asn_hint'] = 'Azure'
            elif 'cloudflare' in rdns_lower:
                result['asn_hint'] = 'Cloudflare'
            elif 'digitalocean' in rdns_lower:
                result['asn_hint'] = 'DigitalOcean'
            elif 'linode' in rdns_lower or 'akamai' in rdns_lower:
                result['asn_hint'] = 'Akamai/Linode'
            elif 'hetzner' in rdns_lower:
                result['asn_hint'] = 'Hetzner'
            elif 'ovh' in rdns_lower:
                result['asn_hint'] = 'OVH'
            elif 'tor' in rdns_lower:
                result['asn_hint'] = 'Tor'
    except (socket.herror, socket.gaierror, OSError):
        pass
    return result


def build_attack_chain(evidence_dir=None):
    """Reconstruct attack kill chain from incident sequence.
    Groups incidents into phases: Recon → Credential Access → Collection → Impact.
    Returns dict with phases, timeline, and attacker profile."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return {'phases': [], 'profile': {}, 'chain_length': 0}

    # Build enriched incident list with timestamps
    enriched = []
    for inc in incidents:
        meta = inc.get('metadata', {})
        ts_str = meta.get('timestamp_iso', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00').split('+')[0])
        except (ValueError, AttributeError):
            ts = None
        token_type = meta.get('token_type', '')
        event = meta.get('event', 'ACCESS').upper()
        enriched.append({
            'incident_id': inc['incident_id'],
            'timestamp': ts,
            'canary_id': meta.get('canary_id', ''),
            'token_type': token_type,
            'event': event,
            'weight': TOKEN_THREAT_WEIGHT.get(token_type, 4),
        })

    # Sort chronologically
    enriched.sort(key=lambda e: e['timestamp'] if e['timestamp'] else datetime.min)

    # Classify into kill chain phases
    phases = defaultdict(list)
    for e in enriched:
        event = e['event']
        weight = e['weight']
        if event in ('ACCESS', 'OPEN') and weight <= 5:
            phase = 'Reconocimiento'
        elif event in ('ACCESS', 'OPEN') and weight >= 6:
            phase = 'Acceso a Credenciales'
        elif event in ('MODIFY', 'MODIFIED'):
            phase = 'Manipulacion'
        elif event in ('DELETE', 'DELETED'):
            phase = 'Destruccion'
        else:
            phase = 'Recoleccion'
        e['phase'] = phase
        phases[phase].append(e)

    # Build phase timeline
    phase_order = ['Reconocimiento', 'Acceso a Credenciales', 'Recoleccion', 'Manipulacion', 'Destruccion']
    phase_timeline = []
    for pname in phase_order:
        if pname not in phases:
            continue
        items = phases[pname]
        first_ts = min((i['timestamp'] for i in items if i['timestamp']), default=None)
        last_ts = max((i['timestamp'] for i in items if i['timestamp']), default=None)
        tokens_hit = list({i['canary_id'] for i in items})
        phase_timeline.append({
            'name': pname,
            'count': len(items),
            'first': first_ts.isoformat() if first_ts else '',
            'last': last_ts.isoformat() if last_ts else '',
            'duration_sec': (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0,
            'tokens': tokens_hit,
        })

    # Attacker profile
    all_accessors = set()
    all_ips = set()
    for inc in incidents:
        acc = extract_accessor(inc['incident_id'], evidence_dir)
        if acc and acc.get('pid'):
            all_accessors.add(f"{acc['user']}:{acc['cmd']}")
        iocs = extract_iocs(inc['incident_id'], evidence_dir)
        for ip in iocs.get('external_ips', []):
            all_ips.add(ip['ip'])
        for ssh in iocs.get('ssh_origins', []):
            all_ips.add(ssh['ip'])

    # Timing analysis
    timestamps = [e['timestamp'] for e in enriched if e['timestamp']]
    total_duration = 0
    avg_interval = 0
    if len(timestamps) >= 2:
        total_duration = (timestamps[-1] - timestamps[0]).total_seconds()
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds()
                      for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals) if intervals else 0

    profile = {
        'unique_accessors': list(all_accessors),
        'unique_ips': list(all_ips),
        'enriched_ips': [enrich_ip(ip) for ip in list(all_ips)[:20]],
        'total_duration_sec': total_duration,
        'avg_interval_sec': round(avg_interval, 1),
        'tokens_targeted': len({e['canary_id'] for e in enriched}),
        'high_value_targeted': sum(1 for e in enriched if e['weight'] >= 8),
        'destructive_events': sum(1 for e in enriched if e['event'] in ('DELETE', 'DELETED', 'MODIFY', 'MODIFIED')),
    }

    # Speed classification
    if total_duration > 0 and total_duration < 60:
        profile['speed'] = 'Automatizado (<1 min)'
    elif total_duration < 300:
        profile['speed'] = 'Rapido (<5 min)'
    elif total_duration < 3600:
        profile['speed'] = 'Moderado (<1 hora)'
    else:
        profile['speed'] = 'Lento/Persistente (>1 hora)'

    # Intent classification
    if profile['destructive_events'] > 0:
        profile['intent'] = 'Destructivo/Ransomware'
    elif profile['high_value_targeted'] > 3:
        profile['intent'] = 'Exfiltracion dirigida'
    elif profile['tokens_targeted'] > 5:
        profile['intent'] = 'Reconocimiento amplio'
    else:
        profile['intent'] = 'Exploratorio'

    return {
        'phases': phase_timeline,
        'enriched': enriched,
        'profile': profile,
        'chain_length': len(enriched),
    }


# ============================================================
# Attacker Fingerprinting & Behavioral Analysis
# ============================================================

# Known tool signatures (process name → tool category)
TOOL_SIGNATURES = {
    # Recon / scanning
    'nmap': ('scanner', 'Network scanner'),
    'masscan': ('scanner', 'Fast port scanner'),
    'zmap': ('scanner', 'Internet-wide scanner'),
    'nikto': ('scanner', 'Web vulnerability scanner'),
    'dirb': ('scanner', 'Web content scanner'),
    'gobuster': ('scanner', 'Directory/file brute-forcer'),
    'ffuf': ('scanner', 'Web fuzzer'),
    'nuclei': ('scanner', 'Vulnerability scanner'),
    'sqlmap': ('scanner', 'SQL injection tool'),
    # Credential tools
    'hydra': ('credential', 'Brute force login'),
    'medusa': ('credential', 'Parallel brute force'),
    'john': ('credential', 'Password cracker'),
    'hashcat': ('credential', 'GPU password cracker'),
    'mimikatz': ('credential', 'Credential dumper'),
    'crackmapexec': ('credential', 'Network credential tool'),
    'impacket': ('credential', 'Network protocol toolkit'),
    # Exfiltration
    'scp': ('exfiltration', 'Secure copy'),
    'rsync': ('exfiltration', 'Remote sync'),
    'curl': ('exfiltration', 'HTTP client'),
    'wget': ('exfiltration', 'HTTP downloader'),
    'nc': ('exfiltration', 'Netcat'),
    'ncat': ('exfiltration', 'Nmap netcat'),
    'socat': ('exfiltration', 'SOcket CAT'),
    # Lateral movement
    'ssh': ('lateral', 'SSH client'),
    'psexec': ('lateral', 'Remote execution'),
    'wmiexec': ('lateral', 'WMI execution'),
    'evil-winrm': ('lateral', 'WinRM shell'),
    # C2 frameworks
    'meterpreter': ('c2', 'Metasploit payload'),
    'beacon': ('c2', 'Cobalt Strike beacon'),
    'sliver': ('c2', 'Sliver C2 implant'),
    # Legitimate but suspicious
    'cat': ('recon_local', 'File reader'),
    'less': ('recon_local', 'File viewer'),
    'more': ('recon_local', 'File pager'),
    'head': ('recon_local', 'File head'),
    'tail': ('recon_local', 'File tail'),
    'grep': ('recon_local', 'Pattern search'),
    'find': ('recon_local', 'File finder'),
    'vim': ('modification', 'Text editor'),
    'nano': ('modification', 'Text editor'),
    'sed': ('modification', 'Stream editor'),
    'cp': ('collection', 'File copy'),
    'mv': ('modification', 'File move'),
    'rm': ('destruction', 'File removal'),
    'python': ('scripted', 'Python interpreter'),
    'python3': ('scripted', 'Python3 interpreter'),
    'perl': ('scripted', 'Perl interpreter'),
    'ruby': ('scripted', 'Ruby interpreter'),
    'bash': ('scripted', 'Shell script'),
    'sh': ('scripted', 'Shell script'),
}


def fingerprint_attacker(evidence_dir=None):
    """Build behavioral profile of the attacker from all evidence.
    Analyzes: tool signatures, access patterns, timing, sophistication.
    Returns dict with fingerprint, tools, patterns, sophistication score."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return {'tools': [], 'patterns': {}, 'sophistication': 0, 'classification': 'unknown'}

    # Collect all accessor commands and timestamps
    tools_seen = Counter()
    tool_categories = Counter()
    timestamps = []
    access_order = []  # (timestamp, token_type, event)
    all_processes = []

    for inc in incidents:
        meta = inc.get('metadata', {})
        ts_str = meta.get('timestamp_iso', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00').split('+')[0])
        except (ValueError, AttributeError):
            ts = None

        iid = inc['incident_id']
        token_type = meta.get('token_type', '')
        event = meta.get('event', 'ACCESS').upper()

        if ts:
            timestamps.append(ts)
            access_order.append({
                'ts': ts, 'token_type': token_type,
                'event': event, 'weight': TOKEN_THREAT_WEIGHT.get(token_type, 4),
            })

        # Extract tools from accessor
        acc = extract_accessor(iid, evidence_dir)
        if acc and acc.get('cmd'):
            cmd = acc['cmd'].strip()
            # Get first word as the command name
            cmd_name = cmd.split()[0].split('/')[-1] if cmd else ''
            if cmd_name in TOOL_SIGNATURES:
                cat, desc = TOOL_SIGNATURES[cmd_name]
                tools_seen[cmd_name] += 1
                tool_categories[cat] += 1

        # Scan processes.txt for known tools
        proc_path = os.path.join(evidence_dir, iid, 'processes.txt')
        if os.path.isfile(proc_path):
            try:
                with open(proc_path, encoding='utf-8', errors='replace') as f:
                    content = f.read(32768)
                for line in content.splitlines():
                    parts = line.split()
                    if len(parts) >= 11:
                        proc_cmd = parts[10].split('/')[-1]
                        if proc_cmd in TOOL_SIGNATURES and proc_cmd not in ('bash', 'sh'):
                            cat, desc = TOOL_SIGNATURES[proc_cmd]
                            if cat not in ('recon_local', 'scripted'):
                                all_processes.append({
                                    'name': proc_cmd, 'category': cat,
                                    'desc': desc, 'full_line': ' '.join(parts[10:])[:100],
                                })
            except OSError:
                pass

    # Deduplicate processes
    seen_procs = set()
    unique_procs = []
    for p in all_processes:
        key = f"{p['name']}:{p['full_line']}"
        if key not in seen_procs:
            seen_procs.add(key)
            unique_procs.append(p)

    # === Timing Analysis ===
    timestamps.sort()
    intervals = []
    if len(timestamps) >= 2:
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds()
                      for i in range(len(timestamps)-1)]

    timing = {}
    if intervals:
        timing['min_interval'] = round(min(intervals), 2)
        timing['max_interval'] = round(max(intervals), 2)
        timing['avg_interval'] = round(sum(intervals) / len(intervals), 2)
        timing['median_interval'] = round(sorted(intervals)[len(intervals)//2], 2)
        timing['stddev'] = round(
            (sum((x - timing['avg_interval'])**2 for x in intervals) / len(intervals)) ** 0.5, 2
        )
        # Automated detection: very regular intervals suggest scripting
        if timing['stddev'] < 2 and timing['avg_interval'] < 5:
            timing['pattern'] = 'automated'
        elif timing['avg_interval'] < 2:
            timing['pattern'] = 'scripted_fast'
        elif timing['stddev'] < timing['avg_interval'] * 0.3:
            timing['pattern'] = 'scripted_regular'
        elif timing['avg_interval'] > 30:
            timing['pattern'] = 'manual_slow'
        else:
            timing['pattern'] = 'manual_interactive'

    # === Access Pattern Analysis ===
    patterns = {}
    if access_order:
        access_order.sort(key=lambda x: x['ts'])
        weights = [a['weight'] for a in access_order]

        # Check if attacker escalates (low-value → high-value)
        if len(weights) >= 3:
            first_third_avg = sum(weights[:len(weights)//3]) / max(len(weights)//3, 1)
            last_third_avg = sum(weights[-len(weights)//3:]) / max(len(weights)//3, 1)
            if last_third_avg > first_third_avg + 2:
                patterns['escalation'] = 'progressive'  # Goes for high-value last
            elif first_third_avg > last_third_avg + 2:
                patterns['escalation'] = 'targeted_first'  # High-value first
            else:
                patterns['escalation'] = 'uniform'  # No clear pattern

        # Token diversity
        unique_types = len({a['token_type'] for a in access_order})
        patterns['token_diversity'] = unique_types
        patterns['total_events'] = len(access_order)

        # Repetition (same token multiple times)
        token_counts = Counter(a['token_type'] for a in access_order)
        max_repeat = max(token_counts.values()) if token_counts else 0
        patterns['max_token_repeat'] = max_repeat
        if max_repeat > 5:
            patterns['repeat_pattern'] = 'obsessive'  # Keeps coming back
        elif max_repeat > 2:
            patterns['repeat_pattern'] = 'thorough'
        else:
            patterns['repeat_pattern'] = 'sweep'  # One-pass through all

    # === Sophistication Scoring (0-100) ===
    sophistication = 0
    soph_reasons = []

    # Tool sophistication
    if tool_categories.get('c2'):
        sophistication += 30
        soph_reasons.append('C2 framework detected (+30)')
    if tool_categories.get('credential'):
        sophistication += 20
        soph_reasons.append('Credential tools (+20)')
    if tool_categories.get('scanner'):
        sophistication += 10
        soph_reasons.append('Scanner tools (+10)')
    if tool_categories.get('lateral'):
        sophistication += 15
        soph_reasons.append('Lateral movement tools (+15)')

    # Access pattern sophistication
    if patterns.get('escalation') == 'progressive':
        sophistication += 15
        soph_reasons.append('Progressive escalation (+15)')
    if patterns.get('repeat_pattern') == 'sweep':
        sophistication += 5
        soph_reasons.append('Clean sweep pattern (+5)')

    # Timing sophistication
    tp = timing.get('pattern', '')
    if tp == 'automated':
        sophistication += 10
        soph_reasons.append('Automated timing (+10)')
    elif tp == 'manual_slow':
        sophistication += 5
        soph_reasons.append('Patient manual access (+5)')

    sophistication = min(100, sophistication)

    # Classification
    if sophistication >= 60:
        classification = 'APT / Profesional'
    elif sophistication >= 40:
        classification = 'Experimentado'
    elif sophistication >= 20:
        classification = 'Intermedio'
    elif sophistication >= 5:
        classification = 'Novato / Script kiddie'
    else:
        classification = 'Oportunista'

    return {
        'tools': [
            {'name': name, 'count': count,
             'category': TOOL_SIGNATURES.get(name, ('unknown', ''))[0],
             'desc': TOOL_SIGNATURES.get(name, ('', 'Unknown'))[1]}
            for name, count in tools_seen.most_common()
        ],
        'suspicious_processes': unique_procs[:20],
        'tool_categories': dict(tool_categories),
        'timing': timing,
        'patterns': patterns,
        'sophistication': sophistication,
        'sophistication_reasons': soph_reasons,
        'classification': classification,
    }


def check_ip_reputation(ip_str, api_key=None):
    """Check IP reputation via AbuseIPDB API (free tier: 1000 checks/day).
    Returns dict with abuse score, reports, country, ISP.
    Falls back to local heuristics if no API key."""
    import urllib.request
    import urllib.error

    result = {
        'ip': ip_str, 'abuse_score': 0, 'total_reports': 0,
        'country': '', 'isp': '', 'domain': '', 'is_tor': False,
        'is_vpn': False, 'source': 'local',
    }

    # Local enrichment first
    local = enrich_ip(ip_str)
    result['rdns'] = local.get('rdns', '')
    result['type'] = local.get('type', 'public')
    result['asn_hint'] = local.get('asn_hint', '')

    # Known Tor exit node patterns
    if local.get('rdns', '').endswith('.torproject.org') or 'tor' in local.get('rdns', '').lower():
        result['is_tor'] = True
        result['abuse_score'] = 75

    # Known VPN/proxy patterns
    rdns = local.get('rdns', '').lower()
    for vpn_hint in ('protonvpn', 'mullvad', 'nordvpn', 'expressvpn', 'surfshark',
                      'privateinternetaccess', 'cyberghost', 'windscribe'):
        if vpn_hint in rdns:
            result['is_vpn'] = True
            result['abuse_score'] = max(result['abuse_score'], 25)
            break

    # Known hosting/cloud (suspicious if connecting to personal machine)
    for cloud in ('amazonaws.com', 'googleusercontent.com', 'azure.com',
                  'digitalocean.com', 'linode.com', 'vultr.com', 'hetzner'):
        if cloud in rdns:
            result['abuse_score'] = max(result['abuse_score'], 40)
            result['isp'] = local.get('asn_hint', cloud)
            break

    # AbuseIPDB API (if key provided)
    api_key = api_key or CFG.get('ABUSEIPDB_API_KEY', '')
    if api_key and result['type'] == 'public':
        try:
            url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_str}&maxAgeInDays=90'
            req = urllib.request.Request(url, headers={
                'Key': api_key,
                'Accept': 'application/json',
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            d = data.get('data', {})
            result['abuse_score'] = d.get('abuseConfidenceScore', 0)
            result['total_reports'] = d.get('totalReports', 0)
            result['country'] = d.get('countryCode', '')
            result['isp'] = d.get('isp', result['isp'])
            result['domain'] = d.get('domain', '')
            result['is_tor'] = d.get('isTor', result['is_tor'])
            result['source'] = 'abuseipdb'
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
            pass  # Fallback to local enrichment

    return result


def enrich_all_ips(evidence_dir=None, api_key=None):
    """Enrich all unique external IPs from all incidents.
    Returns list of enriched IP dicts sorted by abuse score."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    incidents = list_incidents(evidence_dir)

    all_ips = {}  # ip → set of incident_ids
    for inc in incidents:
        iocs = extract_iocs(inc['incident_id'], evidence_dir)
        for ip_info in iocs.get('external_ips', []):
            ip = ip_info['ip']
            if ip not in all_ips:
                all_ips[ip] = set()
            all_ips[ip].add(inc['incident_id'])
        for ssh in iocs.get('ssh_origins', []):
            ip = ssh['ip']
            if ip not in all_ips:
                all_ips[ip] = set()
            all_ips[ip].add(inc['incident_id'])

    enriched = []
    for ip, inc_ids in all_ips.items():
        rep = check_ip_reputation(ip, api_key)
        rep['incident_count'] = len(inc_ids)
        rep['incidents'] = list(inc_ids)[:5]
        enriched.append(rep)

    enriched.sort(key=lambda x: -x['abuse_score'])
    return enriched


def generate_response_playbook(evidence_dir=None):
    """Generate an incident response playbook based on current threat state.
    Analyzes all incidents and produces actionable recommendations."""
    evidence_dir = evidence_dir or CFG['EVIDENCE_DIR']
    chain = build_attack_chain(evidence_dir)
    fingerprint = fingerprint_attacker(evidence_dir)
    enriched_ips = enrich_all_ips(evidence_dir)

    playbook = {
        'generated': datetime.now().isoformat(),
        'threat_level': 'LOW',
        'immediate_actions': [],
        'containment': [],
        'investigation': [],
        'hardening': [],
        'monitoring': [],
    }

    profile = chain.get('profile', {})
    n_incidents = chain.get('chain_length', 0)

    if n_incidents == 0:
        return playbook

    # === Threat Level ===
    if profile.get('destructive_events', 0) > 0:
        playbook['threat_level'] = 'CRITICAL'
    elif profile.get('high_value_targeted', 0) > 3:
        playbook['threat_level'] = 'HIGH'
    elif n_incidents > 10:
        playbook['threat_level'] = 'MEDIUM'
    else:
        playbook['threat_level'] = 'LOW'

    # === Immediate Actions ===
    # Block suspicious IPs
    high_risk_ips = [ip for ip in enriched_ips if ip['abuse_score'] >= 50]
    if high_risk_ips:
        ip_list = ' '.join(ip['ip'] for ip in high_risk_ips[:10])
        playbook['immediate_actions'].append({
            'action': 'Bloquear IPs de alto riesgo',
            'detail': f'{len(high_risk_ips)} IPs con abuse score >= 50',
            'command': f'for ip in {ip_list}; do firewall-cmd --add-rich-rule="rule family=ipv4 source address=$ip reject" 2>/dev/null || iptables -A INPUT -s $ip -j DROP; done',
        })

    # Rotate compromised credentials
    tokens_hit = set()
    for p in chain.get('phases', []):
        tokens_hit.update(p.get('tokens', []))
    if tokens_hit:
        playbook['immediate_actions'].append({
            'action': 'Rotar credenciales comprometidas',
            'detail': f'{len(tokens_hit)} tokens comprometidos: {", ".join(list(tokens_hit)[:5])}',
            'command': '# Revisar y rotar cada credencial que haya sido accedida',
        })

    # Force password change if credential tokens hit
    if profile.get('high_value_targeted', 0) > 0:
        playbook['immediate_actions'].append({
            'action': 'Forzar cambio de passwords',
            'detail': 'Tokens de alto valor accedidos - asumir credenciales comprometidas',
            'command': 'passwd --expire $(whoami)  # Forzar cambio en proximo login',
        })

    # === Containment ===
    if fingerprint.get('timing', {}).get('pattern') in ('automated', 'scripted_fast'):
        playbook['containment'].append({
            'action': 'Detectar y matar procesos automatizados',
            'detail': f'Patron de acceso automatizado detectado (intervalo medio: {fingerprint["timing"].get("avg_interval", "?")}s)',
            'command': 'ps auxf | grep -E "(nmap|hydra|masscan|nuclei|gobuster)" | grep -v grep',
        })

    ssh_ips = [ip for ip in enriched_ips if ip.get('rdns', '') and ':22' in str(ip.get('incidents', []))]
    if profile.get('unique_ips'):
        playbook['containment'].append({
            'action': 'Restringir acceso SSH',
            'detail': f'{len(profile["unique_ips"])} IPs externas observadas',
            'command': '# Verificar authorized_keys y /etc/ssh/sshd_config AllowUsers',
        })

    # === Investigation ===
    playbook['investigation'].append({
        'action': 'Revisar evidencia forense',
        'detail': f'{n_incidents} incidentes con evidencia completa',
        'command': f'ls -la {evidence_dir}/',
    })

    if fingerprint.get('suspicious_processes'):
        proc_names = ', '.join(p['name'] for p in fingerprint['suspicious_processes'][:5])
        playbook['investigation'].append({
            'action': 'Investigar procesos sospechosos',
            'detail': f'Detectados: {proc_names}',
            'command': f'ps auxf | grep -E "({"|".join(p["name"] for p in fingerprint["suspicious_processes"][:5])})"',
        })

    playbook['investigation'].append({
        'action': 'Analizar logs de autenticacion',
        'detail': 'Buscar intentos de login anormales',
        'command': 'journalctl -u sshd --since "24 hours ago" | grep -E "(Failed|Accepted)"',
    })

    # === Hardening ===
    playbook['hardening'].append({
        'action': 'Desplegar tokens adicionales',
        'detail': 'Ampliar la red de engano con tokens frescos',
        'command': 'bash tecnologia-engano.sh  # Secciones 2-6',
    })

    if fingerprint.get('sophistication', 0) >= 40:
        playbook['hardening'].append({
            'action': 'Activar monitoreo avanzado',
            'detail': f'Atacante clasificado como: {fingerprint["classification"]}',
            'command': 'honey-monitor.sh audit-setup && honey-monitor.sh watchd',
        })

    # === Monitoring ===
    playbook['monitoring'].append({
        'action': 'Activar webhook de alertas',
        'detail': 'Notificacion inmediata en cada evento',
        'command': 'honey-monitor.sh webhook-config https://tu-siem/api/alert',
    })
    playbook['monitoring'].append({
        'action': 'Exportar IOCs para compartir',
        'detail': 'STIX 2.1 para MISP/OpenCTI/CERT',
        'command': 'honey-monitor.sh stix-export',
    })

    return playbook


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


# ============================================================
# Lateral Movement Detection
# ============================================================

def detect_lateral_movement(evidence_dir=None):
    """Detect attackers moving between tokens by correlating accessors and timing.

    Returns:
        dict with 'chains' (list of lateral movement chains),
        'cross_token_actors' (actors seen on multiple tokens),
        'risk_score' (0-100 lateral movement risk)
    """
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return {'chains': [], 'cross_token_actors': [], 'risk_score': 0}

    # Collect accessor info per incident
    accessor_map = {}  # accessor_key -> list of (canary_id, timestamp, incident_id)
    for inc in incidents:
        iid = inc['incident_id']
        meta = inc.get('metadata', {})
        canary_id = meta.get('canary_id', 'UNKNOWN')
        ts_str = meta.get('timestamp_iso', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            ts = None

        acc = extract_accessor(iid, evidence_dir)
        if acc and acc.get('pid'):
            key = f"{acc.get('user', '?')}:{acc.get('cmd', '?')}"
        else:
            # Try matching by IP from IOCs
            iocs = extract_iocs(iid, evidence_dir)
            ext_ips = iocs.get('external_ips', [])
            if ext_ips:
                first_ip = ext_ips[0]['ip'] if isinstance(ext_ips[0], dict) else str(ext_ips[0])
                key = f"ip:{first_ip}"
            else:
                continue

        if key not in accessor_map:
            accessor_map[key] = []
        accessor_map[key].append({
            'canary_id': canary_id,
            'timestamp': ts,
            'incident_id': iid,
            'token_type': meta.get('token_type', 'unknown'),
            'event': meta.get('event', ''),
        })

    # Find actors that touched multiple different tokens
    cross_token_actors = []
    chains = []
    for actor, accesses in accessor_map.items():
        unique_tokens = set(a['canary_id'] for a in accesses)
        if len(unique_tokens) < 2:
            continue

        # Sort by time
        timed = [a for a in accesses if a['timestamp']]
        timed.sort(key=lambda x: x['timestamp'])

        cross_token_actors.append({
            'actor': actor,
            'tokens_touched': len(unique_tokens),
            'total_accesses': len(accesses),
            'first_seen': timed[0]['timestamp'].isoformat() if timed else None,
            'last_seen': timed[-1]['timestamp'].isoformat() if timed else None,
            'duration_seconds': (timed[-1]['timestamp'] - timed[0]['timestamp']).total_seconds() if len(timed) >= 2 else 0,
        })

        # Build chain: sequence of token accesses
        chain = []
        for a in timed:
            chain.append({
                'canary_id': a['canary_id'],
                'token_type': a['token_type'],
                'event': a['event'],
                'timestamp': a['timestamp'].isoformat(),
                'incident_id': a['incident_id'],
            })
        if len(chain) >= 2:
            chains.append({
                'actor': actor,
                'steps': chain,
                'length': len(chain),
                'unique_tokens': len(unique_tokens),
            })

    # Risk score: more actors + more tokens = higher risk
    risk = 0
    if cross_token_actors:
        risk += min(40, len(cross_token_actors) * 20)
        max_tokens = max(a['tokens_touched'] for a in cross_token_actors)
        risk += min(30, max_tokens * 10)
        # Speed bonus: fast traversal is more sophisticated
        for actor_info in cross_token_actors:
            dur = actor_info.get('duration_seconds', 0)
            if 0 < dur < 300:  # < 5 min
                risk += 15
                break
            elif 0 < dur < 3600:  # < 1 hour
                risk += 10
                break
        risk = min(100, risk)

    return {
        'chains': sorted(chains, key=lambda c: c['length'], reverse=True),
        'cross_token_actors': cross_token_actors,
        'risk_score': risk,
        'total_actors': len(accessor_map),
        'lateral_actors': len(cross_token_actors),
    }


# ============================================================
# Deception Graph (token mesh visualization)
# ============================================================

# Token proximity: types that logically link together
TOKEN_PROXIMITY = {
    'aws-creds': ['env-prod', 'terraform', 'docker-auth'],
    'env-prod': ['aws-creds', 'db-creds', 'github-auth'],
    'db-creds': ['env-prod', 'password-export', 'backup-prod'],
    'ssh-key': ['vpn-config', 'k8s-config', 'github-auth'],
    'docker-auth': ['aws-creds', 'k8s-config', 'npm-auth'],
    'github-auth': ['ssh-key', 'npm-auth', 'env-prod'],
    'terraform': ['aws-creds', 'k8s-config', 'env-prod'],
    'k8s-config': ['docker-auth', 'terraform', 'ssh-key'],
    'vpn-config': ['ssh-key', 'net-creds', 'k8s-config'],
    'password-export': ['db-creds', 'env-prod', 'financial'],
    'crypto-seed': ['password-export', 'financial'],
    'npm-auth': ['github-auth', 'docker-auth'],
    'financial': ['password-export', 'crypto-seed', 'db-creds'],
    'net-creds': ['vpn-config', 'ssh-key', 'env-prod'],
    'backup-prod': ['db-creds', 'aws-creds'],
}


def build_deception_graph(evidence_dir=None):
    """Build graph of token relationships and attacker traversal paths.

    Returns:
        dict with 'nodes' (tokens), 'edges' (connections),
        'attack_paths' (observed attacker traversals),
        'coverage' (how well the mesh covers the attack surface)
    """
    registry = parse_registry()
    incidents = list_incidents(evidence_dir)

    # Build nodes from registry
    nodes = []
    token_index = {}  # canary_id -> node index
    for i, token in enumerate(registry):
        cid = token.get('canary_id', '')
        ttype = token.get('type', 'unknown')
        nodes.append({
            'id': cid,
            'type': ttype,
            'label': f"{cid[:8]}... ({ttype})",
            'path': token.get('path', ''),
            'incidents': 0,
            'last_access': None,
            'compromised': False,
        })
        token_index[cid] = i

    # Count incidents per token
    for inc in incidents:
        cid = inc.get('metadata', {}).get('canary_id', '')
        if cid in token_index:
            idx = token_index[cid]
            nodes[idx]['incidents'] += 1
            nodes[idx]['compromised'] = True
            ts = inc.get('metadata', {}).get('timestamp_iso', '')
            if ts and (not nodes[idx]['last_access'] or ts > nodes[idx]['last_access']):
                nodes[idx]['last_access'] = ts

    # Build edges from proximity map
    edges = []
    seen_edges = set()
    for node in nodes:
        ttype = node['type']
        neighbors = TOKEN_PROXIMITY.get(ttype, [])
        for neighbor_type in neighbors:
            # Find tokens of this type
            for other in nodes:
                if other['type'] == neighbor_type and other['id'] != node['id']:
                    edge_key = tuple(sorted([node['id'], other['id']]))
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        edges.append({
                            'source': node['id'],
                            'target': other['id'],
                            'type': 'proximity',
                            'source_type': ttype,
                            'target_type': neighbor_type,
                        })

    # Build attack paths from lateral movement
    lateral = detect_lateral_movement(evidence_dir)
    attack_paths = []
    for chain in lateral.get('chains', []):
        path_edges = []
        steps = chain['steps']
        for j in range(len(steps) - 1):
            path_edges.append({
                'from': steps[j]['canary_id'],
                'to': steps[j + 1]['canary_id'],
                'from_type': steps[j]['token_type'],
                'to_type': steps[j + 1]['token_type'],
                'timestamp': steps[j + 1]['timestamp'],
            })
            # Mark these edges as attacked
            for edge in edges:
                ek = tuple(sorted([steps[j]['canary_id'], steps[j + 1]['canary_id']]))
                if tuple(sorted([edge['source'], edge['target']])) == ek:
                    edge['attacked'] = True

        attack_paths.append({
            'actor': chain['actor'],
            'edges': path_edges,
            'length': len(path_edges),
        })

    # Coverage analysis
    all_types = set(TOKEN_PROXIMITY.keys())
    deployed_types = set(n['type'] for n in nodes)
    covered_types = all_types & deployed_types
    missing_types = all_types - deployed_types

    return {
        'nodes': nodes,
        'edges': edges,
        'attack_paths': attack_paths,
        'coverage': {
            'total_types': len(all_types),
            'deployed_types': len(covered_types),
            'missing_types': sorted(missing_types),
            'coverage_pct': round(len(covered_types) / max(len(all_types), 1) * 100, 1),
        },
        'lateral_risk': lateral.get('risk_score', 0),
    }


# ============================================================
# Predictive Analysis
# ============================================================

# Attack progression model: what attackers typically go after next
ATTACK_PROGRESSION = {
    'aws-creds': {'next': ['env-prod', 'terraform', 's3-data'], 'tactic': 'cloud_pivot'},
    'env-prod': {'next': ['db-creds', 'aws-creds', 'api-keys'], 'tactic': 'credential_chain'},
    'db-creds': {'next': ['backup-prod', 'password-export'], 'tactic': 'data_access'},
    'ssh-key': {'next': ['vpn-config', 'k8s-config'], 'tactic': 'lateral_movement'},
    'docker-auth': {'next': ['k8s-config', 'aws-creds'], 'tactic': 'container_escape'},
    'github-auth': {'next': ['npm-auth', 'ssh-key', 'env-prod'], 'tactic': 'supply_chain'},
    'terraform': {'next': ['aws-creds', 'k8s-config'], 'tactic': 'infrastructure'},
    'k8s-config': {'next': ['docker-auth', 'ssh-key'], 'tactic': 'orchestrator_abuse'},
    'vpn-config': {'next': ['ssh-key', 'net-creds'], 'tactic': 'network_pivot'},
    'password-export': {'next': ['db-creds', 'crypto-seed'], 'tactic': 'credential_reuse'},
    'crypto-seed': {'next': [], 'tactic': 'financial_theft'},
    'npm-auth': {'next': ['github-auth', 'env-prod'], 'tactic': 'supply_chain'},
    'financial': {'next': ['crypto-seed'], 'tactic': 'financial_theft'},
    'net-creds': {'next': ['vpn-config', 'env-prod'], 'tactic': 'network_access'},
    'backup-prod': {'next': ['db-creds'], 'tactic': 'data_exfiltration'},
}


def predict_next_target(evidence_dir=None):
    """Based on observed attack patterns, predict what the attacker will target next.

    Returns:
        dict with 'predictions' (likely next targets with confidence),
        'recommendations' (defensive actions), 'observed_pattern'
    """
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return {'predictions': [], 'recommendations': [], 'observed_pattern': 'none'}

    # Get compromised token types in chronological order
    timed_types = []
    for inc in incidents:
        meta = inc.get('metadata', {})
        ts_str = meta.get('timestamp_iso', '')
        ttype = meta.get('token_type', 'unknown')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            ts = None
        timed_types.append({'type': ttype, 'timestamp': ts, 'canary_id': meta.get('canary_id', '')})

    # Sort by time
    timed_types = [t for t in timed_types if t['timestamp']]
    timed_types.sort(key=lambda x: x['timestamp'])

    if not timed_types:
        return {'predictions': [], 'recommendations': [], 'observed_pattern': 'no_timestamps'}

    # Get unique compromised types (order preserved)
    seen = set()
    compromised_sequence = []
    for t in timed_types:
        if t['type'] not in seen:
            seen.add(t['type'])
            compromised_sequence.append(t['type'])

    # Identify pattern
    if len(compromised_sequence) == 1:
        pattern = 'initial_access'
    elif any(prog.get('tactic') == 'lateral_movement'
             for t in compromised_sequence
             for prog in [ATTACK_PROGRESSION.get(t, {})]):
        pattern = 'lateral_movement'
    elif any(prog.get('tactic') == 'credential_chain'
             for t in compromised_sequence
             for prog in [ATTACK_PROGRESSION.get(t, {})]):
        pattern = 'credential_harvesting'
    else:
        pattern = 'exploration'

    # Predict next targets based on last compromised types
    predictions = {}  # type -> confidence score
    recent_types = compromised_sequence[-3:]  # focus on last 3

    for rtype in recent_types:
        progression = ATTACK_PROGRESSION.get(rtype, {})
        next_targets = progression.get('next', [])
        for i, target in enumerate(next_targets):
            if target not in seen:  # Only predict uncompromised
                # Higher confidence for first targets, more recent compromises
                confidence = max(20, 90 - i * 20)
                recency_bonus = (recent_types.index(rtype) + 1) * 5
                score = min(95, confidence + recency_bonus)
                if target not in predictions or predictions[target] < score:
                    predictions[target] = score

    # Sort predictions by confidence
    pred_list = sorted(
        [{'type': t, 'confidence': c, 'tactic': ATTACK_PROGRESSION.get(t, {}).get('tactic', 'unknown')}
         for t, c in predictions.items()],
        key=lambda x: x['confidence'],
        reverse=True,
    )

    # Generate recommendations
    recommendations = []
    if pred_list:
        top = pred_list[0]
        recommendations.append({
            'priority': 'CRITICAL',
            'action': f"Desplegar token honey de tipo '{top['type']}' como trampa anticipada",
            'reason': f"Confianza {top['confidence']}% basada en progresion desde {recent_types[-1]}",
        })
    if pattern == 'lateral_movement':
        recommendations.append({
            'priority': 'HIGH',
            'action': 'Activar segmentacion de red y revisar reglas de firewall',
            'reason': 'Patron de movimiento lateral detectado',
        })
    if pattern == 'credential_harvesting':
        recommendations.append({
            'priority': 'HIGH',
            'action': 'Rotar todas las credenciales de produccion inmediatamente',
            'reason': 'Patron de recoleccion de credenciales activo',
        })
    if len(compromised_sequence) >= 3:
        recommendations.append({
            'priority': 'MEDIUM',
            'action': 'Considerar aislamiento del host comprometido',
            'reason': f'{len(compromised_sequence)} tipos de tokens comprometidos',
        })
    recommendations.append({
        'priority': 'INFO',
        'action': 'Ejecutar honey-monitor.sh respond para respuesta automatica',
        'reason': 'El motor adaptativo desplegara tokens efimeros y generara scripts de bloqueo',
    })

    return {
        'predictions': pred_list[:5],
        'recommendations': recommendations,
        'observed_pattern': pattern,
        'compromised_sequence': compromised_sequence,
        'total_compromised_types': len(compromised_sequence),
        'latest_compromise': timed_types[-1]['type'] if timed_types else None,
    }


# ============================================================
# Threat Intelligence Feed Generation
# ============================================================

def generate_threat_feed(evidence_dir=None, fmt='json'):
    """Generate machine-readable threat intelligence feed from collected IOCs.

    Args:
        fmt: 'json', 'csv', or 'stix'

    Returns:
        dict with 'content' (formatted string), 'ioc_count', 'format'
    """
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return {'content': '', 'ioc_count': 0, 'format': fmt}

    # Collect all IOCs
    all_ips = set()
    all_hashes = set()
    all_domains = set()
    all_users = set()
    ioc_details = []  # For CSV: type, value, context, timestamp, confidence

    for inc in incidents:
        iid = inc['incident_id']
        meta = inc.get('metadata', {})
        ts = meta.get('timestamp_iso', '')
        token_type = meta.get('token_type', 'unknown')

        iocs = extract_iocs(iid, evidence_dir)

        for ip_entry in iocs.get('external_ips', []):
            ip = ip_entry['ip'] if isinstance(ip_entry, dict) else str(ip_entry)
            if ip not in all_ips:
                all_ips.add(ip)
                proc = ip_entry.get('process', '') if isinstance(ip_entry, dict) else ''
                ioc_details.append({
                    'type': 'ipv4-addr',
                    'value': ip,
                    'context': f'Seen accessing {token_type} honey token' + (f' (proc: {proc})' if proc else ''),
                    'first_seen': ts,
                    'confidence': 80,
                    'incident_id': iid,
                })

        for ip_entry in iocs.get('ssh_source_ips', []):
            ip = ip_entry['ip'] if isinstance(ip_entry, dict) else str(ip_entry)
            if ip not in all_ips:
                all_ips.add(ip)
                ioc_details.append({
                    'type': 'ipv4-addr',
                    'value': ip,
                    'context': f'SSH source during honey token incident',
                    'first_seen': ts,
                    'confidence': 85,
                    'incident_id': iid,
                })

        for h in iocs.get('file_hashes', []):
            val = h.get('hash', '')
            if val and val not in all_hashes:
                all_hashes.add(val)
                ioc_details.append({
                    'type': 'file:hashes.SHA-256',
                    'value': val,
                    'context': f"File '{h.get('file', '?')}' in incident {iid}",
                    'first_seen': ts,
                    'confidence': 90,
                    'incident_id': iid,
                })

        # DNS anomalies as domains
        for dns in iocs.get('dns_anomalies', []):
            domain = dns if isinstance(dns, str) else str(dns)
            if domain and domain not in all_domains:
                all_domains.add(domain)
                ioc_details.append({
                    'type': 'domain-name',
                    'value': domain,
                    'context': 'DNS anomaly during honey token incident',
                    'first_seen': ts,
                    'confidence': 60,
                    'incident_id': iid,
                })

        # Suspicious users
        for user_entry in iocs.get('active_users', []):
            uname = user_entry['user'] if isinstance(user_entry, dict) else str(user_entry)
            if uname and uname not in all_users:
                all_users.add(uname)

    if fmt == 'csv':
        lines = ['type,value,context,first_seen,confidence']
        for ioc in ioc_details:
            val = ioc['value'].replace('"', '""')
            ctx = ioc['context'].replace('"', '""')
            lines.append(f'"{ioc["type"]}","{val}","{ctx}","{ioc["first_seen"]}",{ioc["confidence"]}')
        content = '\n'.join(lines)

    elif fmt == 'stix':
        # Minimal STIX 2.1 bundle
        import hashlib
        objects = []
        identity_id = 'identity--securizar-deception-platform'
        objects.append({
            'type': 'identity',
            'spec_version': '2.1',
            'id': identity_id,
            'created': datetime.now().isoformat() + 'Z',
            'modified': datetime.now().isoformat() + 'Z',
            'name': 'Securizar Deception Platform',
            'identity_class': 'system',
        })
        for ioc in ioc_details:
            det_id = hashlib.sha256(f"{ioc['type']}:{ioc['value']}".encode()).hexdigest()[:16]
            objects.append({
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f'indicator--{det_id}',
                'created': ioc['first_seen'] or datetime.now().isoformat() + 'Z',
                'modified': ioc['first_seen'] or datetime.now().isoformat() + 'Z',
                'name': f"{ioc['type']}: {ioc['value']}",
                'description': ioc['context'],
                'indicator_types': ['malicious-activity'],
                'pattern': f"[{ioc['type']}:value = '{ioc['value']}']",
                'pattern_type': 'stix',
                'valid_from': ioc['first_seen'] or datetime.now().isoformat() + 'Z',
                'confidence': ioc['confidence'],
                'created_by_ref': identity_id,
            })
        bundle = {
            'type': 'bundle',
            'id': f'bundle--securizar-feed-{datetime.now().strftime("%Y%m%d")}',
            'objects': objects,
        }
        content = json.dumps(bundle, indent=2, ensure_ascii=False)

    else:  # json
        content = json.dumps({
            'feed_name': 'Securizar Deception IOCs',
            'generated': datetime.now().isoformat(),
            'ioc_count': len(ioc_details),
            'summary': {
                'ips': len(all_ips),
                'hashes': len(all_hashes),
                'domains': len(all_domains),
                'users': len(all_users),
            },
            'indicators': ioc_details,
        }, indent=2, ensure_ascii=False)

    return {
        'content': content,
        'ioc_count': len(ioc_details),
        'format': fmt,
        'summary': {
            'ips': len(all_ips),
            'hashes': len(all_hashes),
            'domains': len(all_domains),
        },
    }


# ============================================================
# Network Trap Log Parser
# ============================================================

def parse_network_log(path=None):
    """Parse honey-network.log from network traps.

    Returns list of dicts with type, port, source, timestamp, extra data.
    """
    if path is None:
        path = os.path.join(os.path.dirname(CFG.get('REGISTRY', '')), 'honey-network.log')
    if not os.path.isfile(path):
        return []

    events = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('|')
                if len(parts) < 3:
                    continue
                entry = {
                    'timestamp': parts[0],
                    'type': parts[1].strip(),
                    'raw': line,
                }
                # Parse key=value pairs from remaining fields
                for part in parts[2:]:
                    if '=' in part:
                        k, _, v = part.partition('=')
                        entry[k.strip()] = v.strip()
                events.append(entry)
    except OSError:
        pass
    return events


# ============================================================
# Deception Analytics Engine
# ============================================================

def compute_dwell_time(evidence_dir=None):
    """Calculate attacker dwell time: duration from first to last access per actor.

    Returns:
        dict with 'per_actor' (list of actor dwell times),
        'per_token' (dwell times grouped by canary_id),
        'overall' (aggregate stats: min/max/mean/median)
    """
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return {'per_actor': [], 'per_token': {}, 'overall': {}}

    # Build actor timeline
    actor_times = defaultdict(list)  # actor_key -> list of timestamps
    token_times = defaultdict(list)  # canary_id -> list of timestamps

    for inc in incidents:
        meta = inc.get('metadata', {})
        canary_id = meta.get('canary_id', 'UNKNOWN')
        ts_str = meta.get('timestamp_iso', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            continue

        token_times[canary_id].append(ts)

        iid = inc['incident_id']
        acc = extract_accessor(iid, evidence_dir)
        if acc and acc.get('pid'):
            key = f"{acc.get('user', '?')}:{acc.get('cmd', '?')}"
        else:
            iocs = extract_iocs(iid, evidence_dir)
            ext_ips = iocs.get('external_ips', [])
            if ext_ips:
                first_ip = ext_ips[0]['ip'] if isinstance(ext_ips[0], dict) else str(ext_ips[0])
                key = f"ip:{first_ip}"
            else:
                key = f"unknown:{canary_id}"
        actor_times[key].append(ts)

    # Calculate dwell times per actor
    per_actor = []
    all_dwells = []
    for actor, times in actor_times.items():
        if len(times) < 2:
            continue
        times.sort()
        dwell_secs = (times[-1] - times[0]).total_seconds()
        per_actor.append({
            'actor': actor,
            'first_seen': times[0].isoformat(),
            'last_seen': times[-1].isoformat(),
            'dwell_seconds': dwell_secs,
            'dwell_human': _format_duration(dwell_secs),
            'event_count': len(times),
        })
        all_dwells.append(dwell_secs)

    per_actor.sort(key=lambda x: -x['dwell_seconds'])

    # Per token dwell
    per_token = {}
    for cid, times in token_times.items():
        times.sort()
        if len(times) >= 2:
            d = (times[-1] - times[0]).total_seconds()
        else:
            d = 0
        per_token[cid] = {
            'dwell_seconds': d,
            'dwell_human': _format_duration(d),
            'event_count': len(times),
            'first': times[0].isoformat(),
            'last': times[-1].isoformat(),
        }

    # Overall stats
    if all_dwells:
        overall = {
            'min_seconds': min(all_dwells),
            'max_seconds': max(all_dwells),
            'mean_seconds': statistics.mean(all_dwells),
            'median_seconds': statistics.median(all_dwells),
            'min_human': _format_duration(min(all_dwells)),
            'max_human': _format_duration(max(all_dwells)),
            'mean_human': _format_duration(statistics.mean(all_dwells)),
            'median_human': _format_duration(statistics.median(all_dwells)),
            'total_actors': len(per_actor),
        }
    else:
        overall = {
            'min_seconds': 0, 'max_seconds': 0,
            'mean_seconds': 0, 'median_seconds': 0,
            'min_human': '0s', 'max_human': '0s',
            'mean_human': '0s', 'median_human': '0s',
            'total_actors': 0,
        }

    return {
        'per_actor': per_actor[:50],
        'per_token': per_token,
        'overall': overall,
    }


def _format_duration(seconds):
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    else:
        return f"{seconds / 86400:.1f}d"


def measure_detection_efficiency(evidence_dir=None):
    """Measure how well the deception platform is detecting threats.

    Returns:
        dict with detection_latency (time from deploy to first hit),
        coverage metrics, alert-to-incident ratios, false positive estimates
    """
    registry = parse_registry()
    alerts = parse_alerts()
    incidents = list_incidents(evidence_dir)

    total_tokens = len(registry)
    if total_tokens == 0:
        return {
            'coverage_pct': 0, 'hit_rate_pct': 0,
            'detection_latency': {}, 'alert_incident_ratio': 0,
            'tokens_never_hit': total_tokens, 'daily_incident_rate': 0,
        }

    # Which tokens have been accessed?
    hit_tokens = set()
    for inc in incidents:
        cid = inc.get('metadata', {}).get('canary_id', '')
        if cid:
            hit_tokens.add(cid)

    tokens_hit = len(hit_tokens)
    hit_rate = round(tokens_hit / max(total_tokens, 1) * 100, 1)

    # Detection latency: time from token creation to first incident
    latencies = []
    for token in registry:
        cid = token.get('canary_id', '')
        created_str = token.get('created', '')
        try:
            created = datetime.strptime(created_str, '%Y-%m-%d')
        except (ValueError, AttributeError):
            continue

        # Find first incident for this token
        first_hit = None
        for inc in reversed(incidents):  # oldest first (reversed since list is newest-first)
            if inc.get('metadata', {}).get('canary_id') == cid:
                ts_str = inc.get('metadata', {}).get('timestamp_iso', '')
                try:
                    first_hit = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    continue
                break

        if first_hit:
            # Make created timezone-aware if first_hit is
            if first_hit.tzinfo and not created.tzinfo:
                created = created.replace(tzinfo=first_hit.tzinfo)
            latency = (first_hit - created).total_seconds()
            if latency >= 0:
                latencies.append(latency)

    if latencies:
        latency_stats = {
            'min_seconds': min(latencies),
            'max_seconds': max(latencies),
            'mean_seconds': statistics.mean(latencies),
            'median_seconds': statistics.median(latencies),
            'min_human': _format_duration(min(latencies)),
            'mean_human': _format_duration(statistics.mean(latencies)),
            'median_human': _format_duration(statistics.median(latencies)),
            'samples': len(latencies),
        }
    else:
        latency_stats = {}

    # Alert-to-incident ratio (higher = noisier / more feedback loops)
    total_alerts = len(alerts)
    total_incidents = len(incidents)
    ratio = round(total_alerts / max(total_incidents, 1), 1)

    # Daily incident rate
    if incidents:
        first_ts = None
        last_ts = None
        for inc in incidents:
            ts_str = inc.get('metadata', {}).get('timestamp_iso', '')
            try:
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                continue
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

        if first_ts and last_ts:
            days = max((last_ts - first_ts).total_seconds() / 86400, 1)
            daily_rate = round(total_incidents / days, 1)
        else:
            daily_rate = 0
    else:
        daily_rate = 0

    # Dedup ratio as false-positive proxy
    dedup = get_alert_dedup_stats(alerts)

    # Token type distribution of hits
    type_hits = Counter()
    for inc in incidents:
        tt = inc.get('metadata', {}).get('token_type', 'unknown')
        type_hits[tt] += 1

    return {
        'total_tokens': total_tokens,
        'tokens_hit': tokens_hit,
        'tokens_never_hit': total_tokens - tokens_hit,
        'hit_rate_pct': hit_rate,
        'coverage_pct': hit_rate,
        'detection_latency': latency_stats,
        'total_alerts': total_alerts,
        'total_incidents': total_incidents,
        'alert_incident_ratio': ratio,
        'daily_incident_rate': daily_rate,
        'dedup_ratio': dedup.get('dedup_ratio', 0),
        'type_hits': dict(type_hits.most_common(15)),
    }


def build_analytics_summary(evidence_dir=None):
    """Build comprehensive analytics summary for the deception platform.

    Returns:
        dict with all key metrics, trends, and health indicators
    """
    registry = parse_registry()
    alerts = parse_alerts()
    incidents = list_incidents(evidence_dir)
    efficiency = measure_detection_efficiency(evidence_dir)
    dwell = compute_dwell_time(evidence_dir)

    # Incident trend: last 7 days vs previous 7 days
    now = datetime.now()
    try:
        if incidents and incidents[0].get('metadata', {}).get('timestamp_iso'):
            sample = incidents[0]['metadata']['timestamp_iso']
            ts = datetime.fromisoformat(sample.replace('Z', '+00:00'))
            if ts.tzinfo:
                now = datetime.now(ts.tzinfo)
    except (ValueError, AttributeError):
        pass

    last_7 = 0
    prev_7 = 0
    last_24h = 0
    for inc in incidents:
        ts_str = inc.get('metadata', {}).get('timestamp_iso', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            continue
        delta = (now - ts).total_seconds()
        if delta <= 86400:
            last_24h += 1
        if delta <= 7 * 86400:
            last_7 += 1
        elif delta <= 14 * 86400:
            prev_7 += 1

    if prev_7 > 0:
        trend_pct = round((last_7 - prev_7) / prev_7 * 100, 1)
    elif last_7 > 0:
        trend_pct = 100.0
    else:
        trend_pct = 0.0

    # Event type distribution
    event_dist = Counter()
    for inc in incidents:
        evt = inc.get('metadata', {}).get('event', 'UNKNOWN')
        event_dist[evt] += 1

    # Threat level distribution
    threat_levels = Counter()
    score_sum = 0
    score_count = 0
    for inc in incidents[:100]:  # Sample last 100
        score_data = compute_threat_score(inc['incident_id'], evidence_dir)
        threat_levels[score_data['level']] += 1
        score_sum += score_data['score']
        score_count += 1

    mean_threat = round(score_sum / max(score_count, 1), 1)

    # Platform health score (0-100)
    health = 100
    if efficiency['tokens_never_hit'] > efficiency['tokens_hit']:
        health -= 10  # Many unused tokens
    if efficiency['alert_incident_ratio'] > 10:
        health -= 15  # Too noisy
    if efficiency['daily_incident_rate'] == 0:
        health -= 20  # No activity
    if not efficiency.get('detection_latency'):
        health -= 10  # Can't measure latency
    elif efficiency['detection_latency'].get('median_seconds', 0) > 7 * 86400:
        health -= 10  # Slow detection
    if len(registry) < 5:
        health -= 15  # Too few tokens
    health = max(0, min(100, health))

    return {
        'health_score': health,
        'total_tokens': len(registry),
        'total_incidents': len(incidents),
        'total_alerts': len(alerts),
        'last_24h': last_24h,
        'last_7d': last_7,
        'prev_7d': prev_7,
        'trend_pct': trend_pct,
        'trend_direction': 'up' if trend_pct > 5 else ('down' if trend_pct < -5 else 'stable'),
        'daily_rate': efficiency['daily_incident_rate'],
        'mean_threat_score': mean_threat,
        'threat_levels': dict(threat_levels),
        'event_distribution': dict(event_dist.most_common(10)),
        'hit_rate_pct': efficiency['hit_rate_pct'],
        'detection_latency': efficiency.get('detection_latency', {}),
        'alert_incident_ratio': efficiency['alert_incident_ratio'],
        'dedup_ratio': efficiency['dedup_ratio'],
        'type_hits': efficiency['type_hits'],
        'dwell_time': dwell['overall'],
        'top_actors': dwell['per_actor'][:5],
        'efficiency': efficiency,
    }


def compute_deception_roi(evidence_dir=None):
    """Estimate the ROI and effectiveness of the deception platform.

    Returns:
        dict with detection value metrics, unique attackers caught,
        estimated early warning value, and effectiveness score
    """
    incidents = list_incidents(evidence_dir)
    registry = parse_registry()
    lateral = detect_lateral_movement(evidence_dir)

    # Unique attackers identified
    unique_actors = set()
    unique_ips = set()
    for inc in incidents:
        iid = inc['incident_id']
        acc = extract_accessor(iid, evidence_dir)
        if acc and acc.get('pid'):
            unique_actors.add(f"{acc.get('user', '?')}:{acc.get('cmd', '?')}")
        iocs = extract_iocs(iid, evidence_dir)
        for ip_entry in iocs.get('external_ips', []):
            ip = ip_entry['ip'] if isinstance(ip_entry, dict) else str(ip_entry)
            unique_ips.add(ip)

    # Evidence collected
    total_evidence_files = 0
    for inc in incidents:
        total_evidence_files += inc.get('file_count', 0)

    # Techniques detected (MITRE coverage)
    techniques_seen = set()
    for inc in incidents[:200]:
        meta = inc.get('metadata', {})
        tt = meta.get('token_type', '')
        evt = meta.get('event', 'ACCESS')
        for t in map_mitre_techniques(tt, evt):
            techniques_seen.add(t['id'])

    # Effectiveness score (0-100)
    effectiveness = 0
    # Breadth: how many tokens are deployed vs recommended
    effectiveness += min(25, len(registry) * 2)
    # Detection: how many unique attackers caught
    effectiveness += min(25, len(unique_actors) * 5)
    # Depth: lateral movement detection active
    if lateral['lateral_actors'] > 0:
        effectiveness += 15
    elif lateral['total_actors'] > 0:
        effectiveness += 5
    # Intelligence: MITRE technique coverage
    effectiveness += min(20, len(techniques_seen) * 2)
    # Activity: incidents being generated
    if len(incidents) > 0:
        effectiveness += 10
    if len(incidents) > 50:
        effectiveness += 5
    effectiveness = min(100, effectiveness)

    # Early warning value (qualitative)
    if lateral['risk_score'] >= 60:
        warning_level = 'CRITICAL'
        warning_desc = 'Movimiento lateral activo detectado - la plataforma esta proporcionando alerta temprana critica'
    elif len(unique_actors) >= 3:
        warning_level = 'HIGH'
        warning_desc = 'Multiples actores detectados - la plataforma identifica amenazas activas'
    elif len(incidents) > 0:
        warning_level = 'MEDIUM'
        warning_desc = 'Actividad detectada - la plataforma funciona como sistema de alerta temprana'
    else:
        warning_level = 'LOW'
        warning_desc = 'Sin actividad - la plataforma esta desplegada pero sin detecciones aun'

    return {
        'effectiveness_score': effectiveness,
        'unique_actors': len(unique_actors),
        'unique_ips': len(unique_ips),
        'total_incidents': len(incidents),
        'total_evidence_files': total_evidence_files,
        'mitre_techniques': len(techniques_seen),
        'technique_list': sorted(techniques_seen),
        'tokens_deployed': len(registry),
        'lateral_risk': lateral['risk_score'],
        'warning_level': warning_level,
        'warning_desc': warning_desc,
        'actors_list': sorted(unique_actors)[:20],
    }


# ============================================================
# TTP Catalog
# ============================================================

def catalog_ttps(evidence_dir=None):
    """Catalog all observed TTPs from incidents into a structured database.

    Returns:
        dict with 'techniques' (aggregated technique usage),
        'tactics' (tactic-level summary), 'procedures' (specific behaviors),
        'kill_chain_coverage' (which kill chain phases are observed)
    """
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return {'techniques': [], 'tactics': {}, 'procedures': [], 'kill_chain_coverage': {}}

    technique_usage = defaultdict(lambda: {
        'count': 0, 'tokens': set(), 'events': set(), 'first_seen': None, 'last_seen': None
    })
    tactic_count = Counter()
    procedures = []

    for inc in incidents[:500]:
        meta = inc.get('metadata', {})
        tt = meta.get('token_type', '')
        evt = meta.get('event', 'ACCESS')
        ts_str = meta.get('timestamp_iso', '')
        canary_id = meta.get('canary_id', '')

        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            ts = None

        techniques = map_mitre_techniques(tt, evt)
        for tech in techniques:
            tid = tech['id']
            tactic = tech.get('tactic', 'unknown')

            technique_usage[tid]['count'] += 1
            technique_usage[tid]['name'] = tech['name']
            technique_usage[tid]['tactic'] = tactic
            technique_usage[tid]['tokens'].add(canary_id)
            technique_usage[tid]['events'].add(evt)
            if ts:
                if not technique_usage[tid]['first_seen'] or ts.isoformat() < technique_usage[tid]['first_seen']:
                    technique_usage[tid]['first_seen'] = ts.isoformat()
                if not technique_usage[tid]['last_seen'] or ts.isoformat() > technique_usage[tid]['last_seen']:
                    technique_usage[tid]['last_seen'] = ts.isoformat()

            tactic_count[tactic] += 1

        # Build procedure descriptions (specific observable behaviors)
        if evt and tt:
            proc_key = f"{evt}:{tt}"
            proc_desc = _describe_procedure(evt, tt, canary_id)
            if proc_desc and len(procedures) < 100:
                procedures.append({
                    'key': proc_key,
                    'description': proc_desc,
                    'token_type': tt,
                    'event': evt,
                    'timestamp': ts_str,
                })

    # Build technique list (serializable)
    tech_list = []
    for tid, data in sorted(technique_usage.items(), key=lambda x: -x[1]['count']):
        tech_list.append({
            'technique_id': tid,
            'name': data['name'],
            'tactic': data['tactic'],
            'count': data['count'],
            'unique_tokens': len(data['tokens']),
            'events': sorted(data['events']),
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
        })

    # Kill chain coverage
    kill_chain_phases = [
        'Reconocimiento', 'Acceso Inicial', 'Ejecucion', 'Persistencia',
        'Escalada de Privilegios', 'Evasion', 'Acceso a Credenciales',
        'Descubrimiento', 'Movimiento Lateral', 'Recoleccion',
        'Exfiltracion', 'Impacto',
    ]
    coverage = {}
    tactic_to_phase = {
        'discovery': 'Descubrimiento',
        'credential_access': 'Acceso a Credenciales',
        'collection': 'Recoleccion',
        'lateral_movement': 'Movimiento Lateral',
        'defense_evasion': 'Evasion',
        'persistence': 'Persistencia',
        'initial_access': 'Acceso Inicial',
        'exfiltration': 'Exfiltracion',
        'impact': 'Impacto',
    }
    for tactic, count in tactic_count.items():
        phase = tactic_to_phase.get(tactic, tactic)
        coverage[phase] = count

    return {
        'techniques': tech_list,
        'tactics': dict(tactic_count.most_common()),
        'procedures': procedures[:50],
        'kill_chain_coverage': {p: coverage.get(p, 0) for p in kill_chain_phases},
        'total_techniques': len(tech_list),
        'total_tactics': len(tactic_count),
    }


def _describe_procedure(event, token_type, canary_id):
    """Generate human-readable procedure description for a TTP."""
    descriptions = {
        ('ACCESS', 'aws-creds'): 'Acceso a credenciales AWS almacenadas localmente',
        ('ACCESS', 'env-prod'): 'Lectura de variables de entorno de produccion',
        ('ACCESS', 'db-creds'): 'Acceso a credenciales de base de datos',
        ('ACCESS', 'ssh-key'): 'Acceso a claves SSH privadas',
        ('ACCESS', 'docker-auth'): 'Lectura de autenticacion Docker registry',
        ('ACCESS', 'github-auth'): 'Acceso a tokens de autenticacion GitHub',
        ('ACCESS', 'terraform'): 'Lectura de credenciales Terraform/IaC',
        ('ACCESS', 'k8s-config'): 'Acceso a configuracion Kubernetes',
        ('ACCESS', 'vpn-config'): 'Lectura de configuracion VPN',
        ('ACCESS', 'password-export'): 'Acceso a exportacion de contrasenas',
        ('ACCESS', 'crypto-seed'): 'Acceso a semillas de billetera crypto',
        ('ACCESS', 'financial'): 'Lectura de datos financieros sensibles',
        ('MODIFY', 'aws-creds'): 'Modificacion de credenciales AWS (posible reemplazo)',
        ('MODIFY', 'env-prod'): 'Alteracion de configuracion de produccion',
        ('MODIFY', 'ssh-key'): 'Modificacion de clave SSH (posible backdoor)',
        ('DELETE', 'aws-creds'): 'Eliminacion de credenciales AWS (antiforense)',
        ('DELETE', 'env-prod'): 'Destruccion de configuracion (sabotaje)',
        ('DELETE', 'password-export'): 'Eliminacion de evidencia de contrasenas',
    }
    # Try exact match first, then partial
    key = (event.replace('CLOSE_WRITE,CLOSE', 'MODIFY').replace('OPEN', 'ACCESS'), token_type)
    desc = descriptions.get(key)
    if not desc:
        for (e, t), d in descriptions.items():
            if e in event and t == token_type:
                return d
    return desc


# ============================================================
# Threat Actor Profiling
# ============================================================

def profile_threat_actors(evidence_dir=None):
    """Group incidents by behavioral similarity to identify distinct threat actors.

    Uses clustering by: access patterns, timing, tools used, token preferences.

    Returns:
        list of actor profiles with behavioral fingerprints
    """
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return []

    # Build behavioral vectors per accessor
    actors = defaultdict(lambda: {
        'incidents': [],
        'timestamps': [],
        'token_types': Counter(),
        'events': Counter(),
        'tools': set(),
        'ips': set(),
    })

    for inc in incidents:
        iid = inc['incident_id']
        meta = inc.get('metadata', {})
        canary_id = meta.get('canary_id', '')
        tt = meta.get('token_type', 'unknown')
        evt = meta.get('event', '')
        ts_str = meta.get('timestamp_iso', '')

        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            ts = None

        # Determine actor key
        acc = extract_accessor(iid, evidence_dir)
        if acc and acc.get('pid'):
            key = f"{acc.get('user', '?')}:{acc.get('cmd', '?')}"
            if acc.get('cmd'):
                actors[key]['tools'].add(acc['cmd'])
        else:
            iocs = extract_iocs(iid, evidence_dir)
            ext_ips = iocs.get('external_ips', [])
            if ext_ips:
                first_ip = ext_ips[0]['ip'] if isinstance(ext_ips[0], dict) else str(ext_ips[0])
                key = f"ip:{first_ip}"
                actors[key]['ips'].add(first_ip)
            else:
                key = f"anon:{canary_id}"

        actors[key]['incidents'].append(iid)
        if ts:
            actors[key]['timestamps'].append(ts)
        actors[key]['token_types'][tt] += 1
        actors[key]['events'][evt] += 1

    # Build profiles
    profiles = []
    for actor_key, data in actors.items():
        if not data['timestamps']:
            continue

        data['timestamps'].sort()
        total_events = len(data['incidents'])

        # Timing analysis
        if len(data['timestamps']) >= 2:
            intervals = [
                (data['timestamps'][i + 1] - data['timestamps'][i]).total_seconds()
                for i in range(len(data['timestamps']) - 1)
            ]
            avg_interval = statistics.mean(intervals) if intervals else 0
            if intervals and len(intervals) >= 2:
                stddev_interval = statistics.stdev(intervals)
            else:
                stddev_interval = 0
        else:
            avg_interval = 0
            stddev_interval = 0

        # Classify behavior
        if avg_interval < 5 and stddev_interval < 2:
            behavior = 'automated'
        elif avg_interval < 30:
            behavior = 'scripted'
        elif avg_interval < 300:
            behavior = 'interactive'
        else:
            behavior = 'slow_persistent'

        # Interest profile: what are they after?
        top_type = data['token_types'].most_common(1)[0][0] if data['token_types'] else 'unknown'
        if top_type in ('aws-creds', 'terraform', 'k8s-config', 'docker-auth'):
            interest = 'cloud_infrastructure'
        elif top_type in ('db-creds', 'password-export', 'env-prod'):
            interest = 'credentials'
        elif top_type in ('ssh-key', 'vpn-config', 'net-creds'):
            interest = 'network_access'
        elif top_type in ('crypto-seed', 'financial'):
            interest = 'financial'
        else:
            interest = 'general'

        # Threat level
        threat = 'LOW'
        if total_events > 20 or len(data['token_types']) > 3:
            threat = 'HIGH'
        elif total_events > 5 or len(data['token_types']) > 1:
            threat = 'MEDIUM'
        if 'DELETE' in str(data['events']):
            threat = 'CRITICAL'

        profiles.append({
            'actor': actor_key,
            'total_events': total_events,
            'unique_tokens': len(data['token_types']),
            'token_types': dict(data['token_types'].most_common()),
            'events': dict(data['events'].most_common()),
            'tools': sorted(data['tools']),
            'ips': sorted(data['ips']),
            'first_seen': data['timestamps'][0].isoformat(),
            'last_seen': data['timestamps'][-1].isoformat(),
            'duration_seconds': (data['timestamps'][-1] - data['timestamps'][0]).total_seconds(),
            'behavior': behavior,
            'interest': interest,
            'threat_level': threat,
            'avg_interval': round(avg_interval, 1),
        })

    profiles.sort(key=lambda p: (-{'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[p['threat_level']],
                                   -p['total_events']))
    return profiles[:30]


# ============================================================
# Detection Rule Generation
# ============================================================

def generate_detection_rules(evidence_dir=None):
    """Auto-generate Sigma-like detection rules from observed attack patterns.

    Returns:
        list of detection rules in Sigma-compatible YAML-like format
    """
    incidents = list_incidents(evidence_dir)
    if not incidents:
        return []

    rules = []

    # Analyze patterns
    token_access_patterns = defaultdict(lambda: {'users': set(), 'commands': set(), 'count': 0})
    event_patterns = Counter()

    for inc in incidents[:300]:
        iid = inc['incident_id']
        meta = inc.get('metadata', {})
        tt = meta.get('token_type', 'unknown')
        evt = meta.get('event', '')
        filepath = meta.get('file_accessed', '')

        acc = extract_accessor(iid, evidence_dir)
        if acc:
            if acc.get('user'):
                token_access_patterns[tt]['users'].add(acc['user'])
            if acc.get('cmd'):
                token_access_patterns[tt]['commands'].add(acc['cmd'])
        token_access_patterns[tt]['count'] += 1
        event_patterns[f"{evt}:{tt}"] += 1

    # Generate rules per token type
    rule_id = 0
    for tt, pattern in token_access_patterns.items():
        if pattern['count'] < 2:
            continue

        rule_id += 1
        commands = sorted(pattern['commands'])
        users = sorted(pattern['users'])

        rule = {
            'id': f'securizar-{rule_id:04d}',
            'title': f'Acceso a Honey Token ({tt})',
            'description': f'Detecta acceso a token de tipo {tt} desplegado por la plataforma de engano. '
                           f'Observado {pattern["count"]} veces.',
            'status': 'experimental',
            'level': 'high' if pattern['count'] > 10 else 'medium',
            'logsource': {
                'category': 'file_access',
                'product': 'linux',
            },
            'detection': {
                'selection': {
                    'TargetFilename|contains': [tt],
                },
            },
            'tags': [f'attack.credential_access', f'deception.{tt}'],
            'falsepositives': ['Backup software', 'System monitoring'],
            'observed_commands': commands[:5],
            'observed_users': users[:5],
            'frequency': pattern['count'],
        }

        if commands:
            rule['detection']['filter_commands'] = {
                'Image|endswith': commands[:3],
            }

        rules.append(rule)

    # Generate time-based rules
    lateral = detect_lateral_movement(evidence_dir)
    if lateral['chains']:
        rule_id += 1
        rules.append({
            'id': f'securizar-{rule_id:04d}',
            'title': 'Movimiento Lateral entre Honey Tokens',
            'description': f'Detecta acceso secuencial a multiples honey tokens por el mismo actor. '
                           f'{len(lateral["chains"])} cadenas observadas.',
            'status': 'experimental',
            'level': 'critical',
            'logsource': {
                'category': 'file_access',
                'product': 'linux',
            },
            'detection': {
                'selection': {
                    'event_type': 'multi_token_access',
                    'timeframe': '5m',
                    'min_tokens': 2,
                },
            },
            'tags': ['attack.lateral_movement', 'deception.chain'],
            'falsepositives': ['Automated backup scanning all files'],
            'observed_chains': len(lateral['chains']),
            'max_chain_length': max(c['length'] for c in lateral['chains']) if lateral['chains'] else 0,
        })

    # Generate event-specific rules
    for evt_key, count in event_patterns.most_common(10):
        if count < 3:
            continue
        evt, tt = evt_key.split(':', 1) if ':' in evt_key else (evt_key, 'unknown')

        if 'DELETE' in evt:
            rule_id += 1
            rules.append({
                'id': f'securizar-{rule_id:04d}',
                'title': f'Eliminacion de Honey Token ({tt})',
                'description': f'Detecta eliminacion de honey token de tipo {tt}. '
                               f'Indica antiforense o sabotaje. Observado {count} veces.',
                'status': 'stable',
                'level': 'critical',
                'logsource': {
                    'category': 'file_delete',
                    'product': 'linux',
                },
                'detection': {
                    'selection': {
                        'TargetFilename|contains': [tt],
                        'EventType': 'DELETE',
                    },
                },
                'tags': ['attack.impact', 'attack.defense_evasion', f'deception.{tt}'],
                'falsepositives': ['Token rotation by admin'],
                'frequency': count,
            })
        elif 'MODIFY' in evt:
            rule_id += 1
            rules.append({
                'id': f'securizar-{rule_id:04d}',
                'title': f'Modificacion de Honey Token ({tt})',
                'description': f'Detecta modificacion de honey token de tipo {tt}. '
                               f'Puede indicar inyeccion de backdoor. Observado {count} veces.',
                'status': 'experimental',
                'level': 'high',
                'logsource': {
                    'category': 'file_change',
                    'product': 'linux',
                },
                'detection': {
                    'selection': {
                        'TargetFilename|contains': [tt],
                        'EventType': 'MODIFY',
                    },
                },
                'tags': ['attack.persistence', f'deception.{tt}'],
                'falsepositives': ['Auto-rotate by honey-monitor'],
                'frequency': count,
            })

    return rules
