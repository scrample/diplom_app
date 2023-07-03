from django.urls import path

from .views import *


urlpatterns = [
    path('', home, name='home'),
    path('scan_results', scan_results, name='scan_results'),
    path('vuln_results', vuln_results, name='vuln_results'),
    path('threats_results', threats_results, name='threats_results'),
    path('secure_tools', secure_tools, name='secure_tools'),
    path('secure_tools_results', secure_tools_results, name='secure_tools_results'),
]