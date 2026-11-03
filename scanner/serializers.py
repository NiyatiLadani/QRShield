from rest_framework import serializers
from .models import ScanResult

class InitiateScanSerializer(serializers.Serializer):
    url = serializers.URLField(required=True)

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = ['task_id', 'target_url', 'risk_score', 'verdict', 'status', 'analysis_details', 'created_at']