"""Views for the deception monitoring dashboard."""
import json
import os
import time
from datetime import datetime, timedelta

from django.conf import settings
from django.http import (
    Http404,
    HttpResponse,
    JsonResponse,
    StreamingHttpResponse,
)
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from . import europol as europol_mod
from . import monitor, parsers

CFG = settings.DECEPTION_CONFIG


def index(request):
    """Dashboard principal: cards de estado, alertas recientes, estadísticas."""
    registry = parsers.parse_registry()
    alerts = parsers.parse_alerts()
    stats = parsers.get_alert_stats(alerts, hours=24)
    token_status = parsers.get_token_status(registry, alerts)
    mon_status = monitor.get_monitor_status()
    incidents = parsers.list_incidents()

    # Severity level
    recent_per_hour = stats['recent'] / max(stats['hours'], 1)
    if recent_per_hour >= CFG['ALERT_CRITICAL_THRESHOLD']:
        severity = 'CRITICO'
    elif recent_per_hour >= CFG['ALERT_WARNING_THRESHOLD']:
        severity = 'WARNING'
    else:
        severity = 'NORMAL'

    dedup = parsers.get_alert_dedup_stats(alerts)

    return render(request, 'dashboard/index.html', {
        'tokens': token_status,
        'alerts': alerts[-20:],
        'stats': stats,
        'monitor': mon_status,
        'incidents': incidents[:5],
        'severity': severity,
        'total_tokens': len(registry),
        'total_alerts': len(alerts),
        'total_incidents': len(incidents),
        'tokens_compromised': sum(1 for t in token_status if t['status'] != 'OK'),
        'dedup': dedup,
    })


def token_list(request):
    """Tabla de todos los tokens con estado."""
    registry = parsers.parse_registry()
    alerts = parsers.parse_alerts()
    token_status = parsers.get_token_status(registry, alerts)
    return render(request, 'dashboard/tokens.html', {
        'tokens': token_status,
    })


def token_detail(request, canary_id):
    """Detalle de un token: metadata, alertas, incidentes relacionados."""
    registry = parsers.parse_registry()
    token = None
    for t in registry:
        if t['canary_id'] == canary_id:
            token = t
            break
    if not token:
        raise Http404('Token no encontrado')

    alerts = parsers.parse_alerts()
    token_alerts = [a for a in alerts if a['canary_id'] == canary_id]

    forensic = parsers.parse_forensic_log()
    token_incidents = [i for i in forensic if i.get('canary_id') == canary_id]

    # File status
    exists = os.path.isfile(token['path'])

    return render(request, 'dashboard/token_detail.html', {
        'token': token,
        'alerts': token_alerts,
        'incidents': token_incidents,
        'exists': exists,
    })


@require_POST
def token_add(request):
    """Register a new token in the registry."""
    canary_id = request.POST.get('canary_id', '').strip()
    path = request.POST.get('path', '').strip()
    token_type = request.POST.get('type', '').strip()
    desc = request.POST.get('desc', '').strip()

    if not all([canary_id, path, token_type]):
        return redirect('dashboard:token_list')

    reg_path = CFG['REGISTRY_PATH']
    date_str = datetime.now().strftime('%Y-%m-%d')
    line = f'{canary_id}|{path}|{token_type}|{date_str}|{desc}\n'

    os.makedirs(os.path.dirname(reg_path), exist_ok=True)
    with open(reg_path, 'a', encoding='utf-8') as f:
        f.write(line)

    return redirect('dashboard:token_list')


@require_POST
def token_delete(request, canary_id):
    """Remove a token from the registry."""
    reg_path = CFG['REGISTRY_PATH']
    if not os.path.isfile(reg_path):
        raise Http404

    with open(reg_path, encoding='utf-8') as f:
        lines = f.readlines()

    new_lines = [l for l in lines if not l.startswith(canary_id + '|')]

    with open(reg_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

    return redirect('dashboard:token_list')


def incident_list(request):
    """Lista de incidentes forenses con filtros."""
    incidents = parsers.list_incidents()

    # Filters
    event_filter = request.GET.get('event', '')
    token_filter = request.GET.get('token', '')

    if event_filter:
        incidents = [
            i for i in incidents
            if i.get('metadata', {}).get('event', '').upper() == event_filter.upper()
        ]
    if token_filter:
        incidents = [
            i for i in incidents
            if token_filter in i.get('metadata', {}).get('canary_id', '')
        ]

    # Pagination
    page = int(request.GET.get('page', 1))
    per_page = CFG['MAX_INCIDENTS_PAGE']
    total = len(incidents)
    start = (page - 1) * per_page
    incidents_page = incidents[start:start + per_page]
    total_pages = (total + per_page - 1) // per_page

    return render(request, 'dashboard/incidents.html', {
        'incidents': incidents_page,
        'page': page,
        'total_pages': total_pages,
        'total': total,
        'event_filter': event_filter,
        'token_filter': token_filter,
    })


def incident_detail(request, incident_id):
    """Detalle completo de un incidente."""
    inc = parsers.parse_incident(incident_id)
    if not inc:
        raise Http404('Incidente no encontrado')

    integrity = parsers.verify_integrity(incident_id)
    accessor = parsers.extract_accessor(incident_id)
    iocs = parsers.extract_iocs(incident_id)
    findings = parsers.extract_key_findings(incident_id)
    threat = parsers.compute_threat_score(incident_id)

    meta = inc.get('metadata', {})
    mitre = parsers.map_mitre_techniques(
        meta.get('token_type', ''), meta.get('event', 'ACCESS')
    )

    return render(request, 'dashboard/incident_detail.html', {
        'incident': inc,
        'metadata': meta,
        'files': inc.get('files', {}),
        'integrity': integrity,
        'accessor': accessor,
        'iocs': iocs,
        'findings': findings,
        'threat': threat,
        'mitre': mitre,
    })


def evidence_file(request, incident_id, filename):
    """View individual evidence file with path traversal validation."""
    safe_path = parsers.safe_evidence_path(incident_id, filename)
    if not safe_path:
        raise Http404('Archivo no encontrado')

    with open(safe_path, encoding='utf-8', errors='replace') as f:
        content = f.read()

    return render(request, 'dashboard/evidence_file.html', {
        'incident_id': incident_id,
        'filename': filename,
        'content': content,
    })


def monitor_status(request):
    """Estado del monitor + controles."""
    status = monitor.get_monitor_status()
    auditd = monitor.get_auditd_status()
    return render(request, 'dashboard/monitor.html', {
        'status': status,
        'auditd': auditd,
    })


@require_POST
def monitor_start(request):
    """Start the honey monitor daemon."""
    ok, output = monitor.start_monitor()
    return redirect('dashboard:monitor_status')


@require_POST
def monitor_stop(request):
    """Stop the honey monitor daemon."""
    ok, output = monitor.stop_monitor()
    return redirect('dashboard:monitor_status')


def europol_form(request):
    """Formulario para seleccionar incidentes para el reporte."""
    incidents = parsers.list_incidents()
    return render(request, 'dashboard/europol_form.html', {
        'incidents': incidents,
        'config': CFG,
    })


@require_POST
def europol_generate(request):
    """Generate and return Europol HTML report."""
    incident_ids = request.POST.getlist('incidents')
    reporter_name = request.POST.get('reporter_name', '')
    reporter_email = request.POST.get('reporter_email', '')
    organization = request.POST.get('organization', CFG['ORGANIZATION_NAME'])
    jurisdiction = request.POST.get('jurisdiction', CFG['JURISDICTION'])
    notes = request.POST.get('notes', '')

    if not incident_ids:
        return redirect('dashboard:europol_form')

    report = europol_mod.generate_report(
        incident_ids=incident_ids,
        reporter_name=reporter_name,
        reporter_email=reporter_email,
        organization=organization,
        jurisdiction=jurisdiction,
        notes=notes,
    )

    action = request.POST.get('action', 'view')
    response = render(request, 'dashboard/europol_report.html', {'report': report})

    if action == 'download':
        response['Content-Disposition'] = (
            f'attachment; filename="europol-{report["case_ref"]}.html"'
        )

    return response


def api_alerts(request):
    """JSON: últimas N alertas (para polling AJAX)."""
    since_str = request.GET.get('since', '')
    since = None
    if since_str:
        try:
            since = datetime.fromisoformat(since_str)
        except ValueError:
            pass

    alerts = parsers.parse_alerts(since=since)
    limit = min(int(request.GET.get('limit', 50)), CFG['MAX_ALERTS_DISPLAY'])
    alerts = alerts[-limit:]

    return JsonResponse({
        'alerts': [
            {
                'timestamp': a['timestamp_str'],
                'event': a['event'],
                'canary_id': a['canary_id'],
                'filepath': a['filepath'],
            }
            for a in alerts
        ],
        'count': len(alerts),
    })


def api_status(request):
    """JSON: estado del monitor + contadores."""
    status = monitor.get_monitor_status()
    alerts = parsers.parse_alerts()
    stats = parsers.get_alert_stats(alerts, hours=1)
    incidents = parsers.list_incidents()

    return JsonResponse({
        'monitor_active': status['active'],
        'monitor_pid': status['pid'],
        'total_tokens': status['tokens'],
        'total_alerts': len(alerts),
        'alerts_last_hour': stats['recent'],
        'total_incidents': len(incidents),
        'auditd': status['auditd'],
    })


def api_alert_stream(request):
    """SSE: StreamingHttpResponse for real-time alerts."""

    def event_stream():
        alert_log = CFG['ALERT_LOG']
        if not os.path.isfile(alert_log):
            yield 'data: {"error": "no alert log"}\n\n'
            return

        # Start from end of file
        with open(alert_log, encoding='utf-8', errors='replace') as f:
            f.seek(0, 2)  # Seek to end
            while True:
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        # Parse inline
                        import re
                        m = re.match(
                            r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\]\s+'
                            r'(\S+)\s+(\S+)\s+(.+)$', line
                        )
                        if m:
                            data = json.dumps({
                                'timestamp': m.group(1),
                                'event': m.group(2),
                                'canary_id': m.group(3),
                                'filepath': m.group(4),
                            })
                            yield f'data: {data}\n\n'
                else:
                    time.sleep(1)
                    yield ': keepalive\n\n'

    response = StreamingHttpResponse(
        event_stream(),
        content_type='text/event-stream'
    )
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response


def timeline(request):
    """Vista cronologica unificada de todos los eventos."""
    limit = min(int(request.GET.get('limit', 100)), 500)
    events = parsers.build_timeline(limit=limit)

    # Dedup: collapse consecutive alerts for same token within 2 seconds
    deduped = []
    for e in events:
        if deduped and e['type'] == 'alert' and deduped[-1]['type'] == 'alert':
            prev = deduped[-1]
            if (prev['canary_id'] == e['canary_id']
                    and prev['timestamp'] and e['timestamp']
                    and abs((prev['timestamp'] - e['timestamp']).total_seconds()) < 2):
                if 'dup_count' not in prev:
                    prev['dup_count'] = 1
                prev['dup_count'] += 1
                continue
        deduped.append(e)

    return render(request, 'dashboard/timeline.html', {
        'events': deduped,
        'total_raw': len(events),
        'total_deduped': len(deduped),
        'limit': limit,
    })


def api_export_incidents(request):
    """JSON export of all incidents with IOCs and findings."""
    incidents = parsers.list_incidents()
    export = []
    for inc in incidents:
        iid = inc['incident_id']
        iocs = parsers.extract_iocs(iid)
        accessor = parsers.extract_accessor(iid)
        findings = parsers.extract_key_findings(iid)
        export.append({
            'incident_id': iid,
            'metadata': inc.get('metadata', {}),
            'file_count': inc.get('file_count', 0),
            'accessor': accessor,
            'iocs': {
                'external_ips': iocs.get('external_ips', []),
                'ssh_origins': iocs.get('ssh_origins', []),
                'arp_anomalies': iocs.get('arp_anomalies', 0),
                'vpn_active': iocs.get('vpn_active', False),
                'file_hashes': iocs.get('file_hashes', []),
            },
            'findings': findings,
        })

    response = JsonResponse({'incidents': export, 'count': len(export)})
    if request.GET.get('download'):
        response['Content-Disposition'] = (
            f'attachment; filename="securizar-incidents-{datetime.now():%Y%m%d-%H%M%S}.json"'
        )
    return response


def correlation(request):
    """Incident correlation: grouped by token, feedback loop detection."""
    corr = parsers.correlate_incidents()
    dedup = parsers.get_alert_dedup_stats()
    registry = parsers.parse_registry()

    # Enrich groups with token type
    type_map = {t['canary_id']: t['type'] for t in registry}
    groups = []
    for cid, count in sorted(corr['groups'].items(), key=lambda x: -x[1]):
        groups.append({
            'canary_id': cid,
            'count': count,
            'type': type_map.get(cid, 'unknown'),
        })

    return render(request, 'dashboard/correlation.html', {
        'groups': groups,
        'feedback_loops': corr['feedback_loops'],
        'unique_tokens': corr['unique_tokens'],
        'unique_accessors': corr['unique_accessors'],
        'total_incidents': corr['total_incidents'],
        'dedup': dedup,
    })


def attack_map(request):
    """MITRE ATT&CK heatmap from all incidents."""
    heatmap_data = parsers.build_mitre_heatmap()
    return render(request, 'dashboard/attack_map.html', {
        'heatmap': heatmap_data['heatmap'],
        'total_techniques': heatmap_data['total_techniques'],
        'total_incidents': heatmap_data['total_incidents'],
        'top_techniques': heatmap_data['top_techniques'],
    })


def threat_overview(request):
    """Threat intelligence: attack chain, attacker profile, scores."""
    chain = parsers.build_attack_chain()
    incidents = parsers.list_incidents()

    # Compute threat scores for all incidents
    scores = []
    for inc in incidents[:50]:
        s = parsers.compute_threat_score(inc['incident_id'])
        s['incident_id'] = inc['incident_id']
        s['event'] = inc.get('metadata', {}).get('event', '?')
        s['token_type'] = inc.get('metadata', {}).get('token_type', '?')
        s['canary_id'] = inc.get('metadata', {}).get('canary_id', '?')
        scores.append(s)

    # Aggregate score
    if scores:
        avg_score = sum(s['score'] for s in scores) / len(scores)
        max_score = max(s['score'] for s in scores)
    else:
        avg_score = 0
        max_score = 0

    # Sort by score descending for the top threats table
    scores.sort(key=lambda s: -s['score'])

    return render(request, 'dashboard/threat_overview.html', {
        'chain': chain,
        'phases': chain['phases'],
        'profile': chain['profile'],
        'scores': scores[:20],
        'avg_score': round(avg_score),
        'max_score': max_score,
        'total_incidents': chain['chain_length'],
    })


def fingerprint_view(request):
    """Attacker fingerprinting and behavioral analysis."""
    fp = parsers.fingerprint_attacker()
    return render(request, 'dashboard/fingerprint.html', {
        'fingerprint': fp,
        'tools': fp['tools'],
        'processes': fp['suspicious_processes'],
        'categories': fp['tool_categories'],
        'timing': fp['timing'],
        'patterns': fp['patterns'],
        'sophistication': fp['sophistication'],
        'reasons': fp['sophistication_reasons'],
        'classification': fp['classification'],
    })


def playbook_view(request):
    """Auto-generated incident response playbook."""
    pb = parsers.generate_response_playbook()
    return render(request, 'dashboard/playbook.html', {
        'playbook': pb,
        'threat_level': pb['threat_level'],
        'immediate': pb['immediate_actions'],
        'containment': pb['containment'],
        'investigation': pb['investigation'],
        'hardening': pb['hardening'],
        'monitoring': pb['monitoring'],
    })


def ip_reputation(request):
    """IP reputation lookup and enrichment."""
    enriched = parsers.enrich_all_ips()
    # Separate by risk level
    critical = [ip for ip in enriched if ip['abuse_score'] >= 70]
    high = [ip for ip in enriched if 40 <= ip['abuse_score'] < 70]
    medium = [ip for ip in enriched if 10 <= ip['abuse_score'] < 40]
    low = [ip for ip in enriched if ip['abuse_score'] < 10]

    return render(request, 'dashboard/ip_reputation.html', {
        'enriched': enriched[:50],
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'total': len(enriched),
    })


def deception_graph(request):
    """Deception mesh: token graph, attack paths, coverage analysis."""
    graph = parsers.build_deception_graph()
    return render(request, 'dashboard/deception_graph.html', {
        'nodes': graph['nodes'],
        'edges': graph['edges'],
        'attack_paths': graph['attack_paths'],
        'coverage': graph['coverage'],
        'lateral_risk': graph['lateral_risk'],
        'total_nodes': len(graph['nodes']),
        'total_edges': len(graph['edges']),
        'compromised': sum(1 for n in graph['nodes'] if n['compromised']),
    })


def lateral_movement(request):
    """Lateral movement detection and attack chain analysis."""
    lateral = parsers.detect_lateral_movement()
    predictions = parsers.predict_next_target()
    return render(request, 'dashboard/lateral_movement.html', {
        'chains': lateral['chains'],
        'cross_token_actors': lateral['cross_token_actors'],
        'risk_score': lateral['risk_score'],
        'total_actors': lateral['total_actors'],
        'lateral_actors': lateral['lateral_actors'],
        'predictions': predictions['predictions'],
        'recommendations': predictions['recommendations'],
        'observed_pattern': predictions['observed_pattern'],
        'compromised_sequence': predictions.get('compromised_sequence', []),
    })


def threat_feed(request):
    """Threat intelligence feed: download IOCs in various formats."""
    fmt = request.GET.get('format', '')
    if fmt in ('json', 'csv', 'stix'):
        feed = parsers.generate_threat_feed(fmt=fmt)
        content = feed['content']
        if fmt == 'json' or fmt == 'stix':
            ct = 'application/json'
            ext = 'json'
        else:
            ct = 'text/csv'
            ext = 'csv'
        response = HttpResponse(content, content_type=ct)
        response['Content-Disposition'] = (
            f'attachment; filename="securizar-threat-feed-{datetime.now():%Y%m%d}.{ext}"'
        )
        return response

    # Show feed overview page
    feed_json = parsers.generate_threat_feed(fmt='json')
    network = parsers.parse_network_log()
    return render(request, 'dashboard/threat_feed.html', {
        'ioc_count': feed_json['ioc_count'],
        'summary': feed_json['summary'],
        'network_events': len(network),
        'network_recent': network[-10:] if network else [],
    })


def ttp_catalog(request):
    """TTP catalog: observed techniques, tactics, procedures."""
    ttps = parsers.catalog_ttps()
    actors = parsers.profile_threat_actors()
    rules = parsers.generate_detection_rules()
    return render(request, 'dashboard/ttp_catalog.html', {
        'techniques': ttps['techniques'],
        'tactics': ttps['tactics'],
        'procedures': ttps['procedures'][:30],
        'kill_chain': ttps['kill_chain_coverage'],
        'total_techniques': ttps['total_techniques'],
        'total_tactics': ttps['total_tactics'],
        'actors': actors[:15],
        'rules': rules,
    })


def analytics(request):
    """Comprehensive deception platform analytics."""
    summary = parsers.build_analytics_summary()
    roi = parsers.compute_deception_roi()
    dwell = parsers.compute_dwell_time()
    return render(request, 'dashboard/analytics.html', {
        'summary': summary,
        'roi': roi,
        'dwell': dwell,
        'health': summary['health_score'],
        'trend_pct': summary['trend_pct'],
        'trend_direction': summary['trend_direction'],
        'threat_levels': summary['threat_levels'],
        'event_dist': summary['event_distribution'],
        'type_hits': summary['type_hits'],
        'detection_latency': summary.get('detection_latency', {}),
        'dwell_overall': dwell['overall'],
        'top_actors': dwell['per_actor'][:10],
        'effectiveness': roi['effectiveness_score'],
        'warning_level': roi['warning_level'],
        'warning_desc': roi['warning_desc'],
    })


def settings_view(request):
    """View/modify panel configuration."""
    if request.method == 'POST':
        # Update modifiable settings
        for key in ['POLL_INTERVAL_MS', 'MAX_ALERTS_DISPLAY', 'ALERT_CRITICAL_THRESHOLD',
                     'ALERT_WARNING_THRESHOLD']:
            val = request.POST.get(key, '')
            if val.isdigit():
                CFG[key] = int(val)
        for key in ['ORGANIZATION_NAME', 'REPORTER_NAME', 'REPORTER_EMAIL', 'JURISDICTION']:
            val = request.POST.get(key, '')
            if val:
                CFG[key] = val
        return redirect('dashboard:settings_view')

    return render(request, 'dashboard/settings.html', {
        'config': CFG,
    })
