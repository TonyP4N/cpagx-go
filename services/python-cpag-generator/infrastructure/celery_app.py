#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Celery application for all versions (v1 and v2)
"""

import os
from celery import Celery
from celery.schedules import crontab


celery_app = Celery(
    'cpag_generator',
    broker=os.getenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672/'),
    backend=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
    include=['api.v1.tasks', 'api.v2.tasks']
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,

    # Define queues
    task_default_queue='celery',
    task_queues={
        'celery': {
            'exchange': 'celery',
            'routing_key': 'celery',
        },
        'cpag_generation': {
            'exchange': 'cpag_generation',
            'routing_key': 'cpag_generation',
        },
        'network_analysis': {
            'exchange': 'network_analysis',
            'routing_key': 'network_analysis',
        },
        'graph_building': {
            'exchange': 'graph_building',
            'routing_key': 'graph_building',
        },
    },

    # Route tasks per module
    task_routes={
        'api.v1.tasks.generate_cpag': {'queue': 'cpag_generation'},
        'api.v2.tasks.generate_cpag': {'queue': 'cpag_generation'},
        'api.v2.tasks.analyze_network': {'queue': 'network_analysis'},
        'api.v2.tasks.build_graph': {'queue': 'graph_building'},
        'api.v2.tasks.collect_metrics': {'queue': 'celery'},
        'api.v2.tasks.health_check': {'queue': 'celery'},
        'api.v2.tasks.cleanup_old_tasks': {'queue': 'celery'},
        # 兼容旧的任务名称
        'tasks.collect_metrics': {'queue': 'celery'},
        'tasks.health_check': {'queue': 'celery'},
        'tasks.cleanup_old_tasks': {'queue': 'celery'},
    },

    task_acks_late=True,
    worker_prefetch_multiplier=int(os.getenv('CELERY_WORKER_PREFETCH_MULTIPLIER', 1)),
    task_compression='gzip',
    result_compression='gzip',

    task_annotations={
        'api.v1.tasks.generate_cpag': {
            'rate_limit': '20/m',
            'time_limit': int(os.getenv('CELERY_TASK_TIME_LIMIT', 1800)),
            'soft_time_limit': int(os.getenv('CELERY_TASK_SOFT_TIME_LIMIT', 1200)),
            'retry_backoff': True,
            'max_retries': int(os.getenv('CELERY_MAX_RETRIES', 3)),
        },
        'api.v2.tasks.generate_cpag': {
            'rate_limit': '10/m',
            'time_limit': int(os.getenv('CELERY_TASK_TIME_LIMIT', 3600)),
            'soft_time_limit': int(os.getenv('CELERY_TASK_SOFT_TIME_LIMIT', 3000)),
            'retry_backoff': True,
            'max_retries': int(os.getenv('CELERY_MAX_RETRIES', 3)),
        },
    },

    result_expires=int(os.getenv('REDIS_TTL', 3600)),
    result_persistent=True,

    worker_send_task_events=True,
    task_send_sent_event=True,

    # Use v2 maintenance tasks by default
    beat_schedule={
        'cleanup-old-tasks': {
            'task': 'api.v2.tasks.cleanup_old_tasks',
            'schedule': crontab(hour=2, minute=0),
        },
        'health-check': {
            'task': 'api.v2.tasks.health_check',
            'schedule': 300.0,
        },
        'metrics-collection': {
            'task': 'api.v2.tasks.collect_metrics',
            'schedule': 60.0,
        },
    }
)

if __name__ == '__main__':
    celery_app.start()


