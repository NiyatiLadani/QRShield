from django.urls import path
from .views import InitiateScanView, ScanStatusView

urlpatterns = [
    path('scan/', InitiateScanView.as_view(), name='initiate-scan'),
    path('status/<str:task_id>/', ScanStatusView.as_view(), name='scan-status'),
]