"""Operator-selected fixed resources; absent selection preserves legacy defaults.

These are engineering budgets, never claims of demonstrated target capacity.
They cannot be raised by a task profile or an uploaded file.
"""
PROFILES = {
    'r19-dev-s100-1': {
        'memory_bytes': 2*1024**3, 'cpus': '2', 'timeout': 900,
        'output_bytes': 512*1024**2, 'host_budget_bytes': 4*1024**3,
        'min_free_bytes': 256*1024**2, 'transfer_seconds': 180, 'publication_seconds':180, 'cpu_seconds':1200, 'temporary_bytes':514*1024**2,
    },
    'engineering-capacity-1': {
        'memory_bytes': 8*1024**3, 'cpus': '4', 'timeout': 1800,
        'output_bytes': 1024**3, 'host_budget_bytes': 12*1024**3,
        'min_free_bytes': 8*1024**3, 'transfer_seconds': 600, 'publication_seconds':600, 'cpu_seconds':6000, 'temporary_bytes':4*1024**3,
    },
}


# New execution/storage strategy, identical numerical resource ceilings.
PROFILES["engineering-capacity-2"]=dict(PROFILES["engineering-capacity-1"])

def resolve(name):
    if name is None:
        return None
    if not isinstance(name,str) or name not in PROFILES:
        raise ValueError('unknown operator resource profile')
    return dict(PROFILES[name])

# Explicit DAG6 service resources; numerical engineering ceilings are unchanged.
PROFILES["storage-budget-2"]=dict(PROFILES["engineering-capacity-1"])
