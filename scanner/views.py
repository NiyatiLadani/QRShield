from django.shortcuts import render

# Create your views here.
#CC

import uuid
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import InitiateScanSerializer, ScanResultSerializer
from .tasks import run_quishing_analysis_task
from .models import ScanResult

logger = logging.getLogger(__name__)

class InitiateScanView(APIView):
    def post(self, request):
        serializer = InitiateScanSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        target_url = serializer.validated_data['url']
        task_id = str(uuid.uuid4())

        # Pre-create processing record in database first to eliminate race condition
        ScanResult.objects.create(
            task_id=task_id,
            target_url=target_url,
            status='PROCESSING'
        )

        try:
            # Enqueue task in Celery/Redis with explicit task_id
            run_quishing_analysis_task.apply_async(args=[target_url], task_id=task_id)
        except Exception as e:
            logger.error(f"Failed to enqueue Celery task: {str(e)}")
            ScanResult.objects.filter(task_id=task_id).update(
                status='FAILED',
                verdict='ERROR',
                analysis_details={"error": f"Task queuing failed: {str(e)}"}
            )
            return Response({
                "task_id": task_id,
                "status": "FAILED",
                "error": "Failed to enqueue background analysis task."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "task_id": task_id,
            "status": "PROCESSING",
            "message": "Analysis started in background queue."
        }, status=status.HTTP_202_ACCEPTED)

class ScanStatusView(APIView):
    def get(self, request, task_id):
        try:
            record = ScanResult.objects.get(task_id=task_id)
            serializer = ScanResultSerializer(record)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ScanResult.DoesNotExist:
            return Response({"error": "Task ID not found"}, status=status.HTTP_404_NOT_FOUND)
