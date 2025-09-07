from pydantic import BaseModel
from typing import List, Optional


class CPAGResponse(BaseModel):
    id: str
    task_id: str
    status: str
    created_at: str
    result_url: Optional[str] = None
    error: Optional[str] = None
    version: str


class TaskInfo(BaseModel):
    task_id: str
    status: str
    created_at: str
    version: str
    files: List[str] = []
    result_url: Optional[str] = None
    file_size: Optional[int] = None  # File size in bytes
    file_name: Optional[str] = None  # Original filename


