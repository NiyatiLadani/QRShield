from django.db import models

# Create your models here.
#CC

class ScanResult(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]

    task_id = models.CharField(max_length=255, unique=True, db_index=True)
    target_url = models.TextField()
    risk_score = models.FloatField(default=0.0)
    verdict = models.CharField(max_length=50, default="PENDING")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    analysis_details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.target_url} | {self.verdict} ({self.risk_score})"