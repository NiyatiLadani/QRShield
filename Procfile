web: gunicorn backend_core.wsgi:application --bind 0.0.0.0:$PORT --workers 3
worker: celery -A backend_core worker --loglevel=info
