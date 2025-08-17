import os
from pydantic import BaseModel


class ServiceConfig(BaseModel):
    port_v1: int = int(os.getenv("PORT_V1", 8000))
    port_v2: int = int(os.getenv("PORT_V2", 8002))
    output_dir_v1: str = os.getenv("OUTPUT_DIR_V1", "outputs/v1")
    output_dir_v2: str = os.getenv("OUTPUT_DIR_V2", "outputs/v2")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    rabbitmq_url: str = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    cors_allow_origins: str = os.getenv("CORS_ALLOW_ORIGINS", "*")
    # 并发控制配置
    max_concurrent_tasks_v1: int = int(os.getenv("MAX_CONCURRENT_TASKS_V1", "5"))
    max_concurrent_tasks_v2: int = int(os.getenv("MAX_CONCURRENT_TASKS_V2", "3"))


def get_config() -> ServiceConfig:
    """获取服务配置"""
    return ServiceConfig()


