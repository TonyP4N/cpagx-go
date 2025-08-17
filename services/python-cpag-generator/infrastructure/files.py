import os
import tempfile
import uuid
from typing import Optional, Tuple, List


def ensure_output_dir(base_dir: str, task_id: str) -> str:
    out_dir = os.path.abspath(os.path.join(base_dir, task_id))
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


async def save_upload_to_temp(upload, suffix: str) -> str:
    # 使用uploads目录而不是/tmp，确保Celery worker可以访问
    uploads_dir = os.path.join(os.getcwd(), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    
    # 生成唯一的文件名
    filename = f"{uuid.uuid4()}{suffix}"
    file_path = os.path.join(uploads_dir, filename)
    
    with open(file_path, 'wb') as temp_file:
        content = await upload.read()
        temp_file.write(content)
        return file_path


def cleanup_temp_file(path: Optional[str]):
    if not path:
        return
    try:
        os.unlink(path)
    except Exception:
        pass


def cleanup_temp_files(paths: List[Optional[str]]):
    for p in paths:
        cleanup_temp_file(p)


def get_extension(filename: Optional[str]) -> str:
    if not filename:
        return ""
    return os.path.splitext(filename)[1].lower()


def is_allowed_extension(filename: Optional[str], allowed_exts: List[str]) -> bool:
    ext = get_extension(filename)
    return ext in allowed_exts


async def save_upload_validated(upload, allowed_exts: List[str]) -> str:
    """Validate extension and save UploadFile to a temp file; return temp path.
    Raise ValueError if invalid.
    """
    ext = get_extension(getattr(upload, 'filename', None))
    if ext not in allowed_exts:
        raise ValueError(f"Unsupported format: {ext}. Allowed: {', '.join(allowed_exts)}")
    return await save_upload_to_temp(upload, ext)


def assign_compatible_file_param(file_obj, pcap_file, csv_file):
    """Compat param: if 'file' is used, dispatch to pcap or csv by extension.
    Return (pcap_file, csv_file).
    """
    if file_obj is not None and pcap_file is None and csv_file is None:
        ext = get_extension(getattr(file_obj, 'filename', None))
        if ext in [".pcap", ".pcapng"]:
            pcap_file = file_obj
        elif ext in [".csv"]:
            csv_file = file_obj
        else:
            raise ValueError("Unsupported file format for 'file'. Use pcap_file/csv_file explicitly.")
    return pcap_file, csv_file


