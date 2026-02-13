from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.index, name='index'),
    path('tokens/', views.token_list, name='token_list'),
    path('tokens/add/', views.token_add, name='token_add'),
    path('tokens/<str:canary_id>/', views.token_detail, name='token_detail'),
    path('tokens/<str:canary_id>/delete/', views.token_delete, name='token_delete'),
    path('incidents/', views.incident_list, name='incident_list'),
    path('incidents/<str:incident_id>/', views.incident_detail, name='incident_detail'),
    path('incidents/<str:incident_id>/evidence/<str:filename>', views.evidence_file, name='evidence_file'),
    path('monitor/', views.monitor_status, name='monitor_status'),
    path('monitor/start/', views.monitor_start, name='monitor_start'),
    path('monitor/stop/', views.monitor_stop, name='monitor_stop'),
    path('europol/', views.europol_form, name='europol_form'),
    path('europol/generate/', views.europol_generate, name='europol_generate'),
    path('api/alerts/', views.api_alerts, name='api_alerts'),
    path('api/status/', views.api_status, name='api_status'),
    path('api/alerts/stream/', views.api_alert_stream, name='api_alert_stream'),
    path('settings/', views.settings_view, name='settings_view'),
]
