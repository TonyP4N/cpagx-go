"""Explicit operator-scoped database capability; validation defaults stay narrow.

Actual deployed names are passed unchanged to PostgreSQL. No environment flag,
name alias or mutable global subprocess patch can enable deployment access.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import re
import subprocess


@dataclass(frozen=True)
class KubernetesPostgres:
    context: str
    namespace: str
    pod: str
    pod_uid: str
    container: str = 'postgres'

    def __post_init__(self):
        for value in (self.context,self.namespace,self.pod,self.container):
            if not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',value):
                raise ValueError('explicit Kubernetes endpoint required')
        if not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',self.pod_uid):
            raise ValueError('immutable PostgreSQL Pod UID required')

    def command(self, arguments, interactive):
        prefix=['kubectl','--context',self.context,'-n',self.namespace]
        observed=subprocess.run([*prefix,'get','pod',self.pod,'-o','jsonpath={.metadata.uid}'],
                                check=True,capture_output=True,text=True,timeout=15).stdout
        if observed!=self.pod_uid:raise ValueError('PostgreSQL Pod replaced')
        return [*prefix,'exec',*(['-i'] if interactive else []),self.pod,'-c',self.container,'--',*arguments]

_ACTIVE = ContextVar('cpag_backup_deployment_databases', default=None)


def _name(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', value)
            or value.lower() in ('postgres', 'template0', 'template1') or value.lower().startswith('pg_')):
        raise ValueError('explicit non-system deployment database name required')


@dataclass(frozen=True)
class DeploymentDatabases:
    container: str
    source: str
    restore: str
    kubernetes: KubernetesPostgres | None = None

    def __post_init__(self):
        if not isinstance(self.container, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', self.container):
            raise ValueError('explicit Docker PostgreSQL container required')
        _name(self.source); _name(self.restore)
        if self.source == self.restore:
            raise ValueError('new restore database must differ from source database')
        if self.kubernetes is not None and (not isinstance(self.kubernetes,KubernetesPostgres) or self.container!=self.kubernetes.pod):
            raise ValueError('Kubernetes endpoint must match database policy')


def database_command(container, arguments, interactive=True):
    policy=_ACTIVE.get()
    if policy is not None and policy.kubernetes is not None:
        if container!=policy.container:raise ValueError('database endpoint outside explicit deployment policy')
        return policy.kubernetes.command(arguments,interactive)
    return ['docker','exec',*(['-i'] if interactive else []),container,*arguments]


@contextmanager
def deployment_databases(policy):
    if not isinstance(policy, DeploymentDatabases) or _ACTIVE.get() is not None:
        raise ValueError('one explicit deployment database policy required')
    token = _ACTIVE.set(policy)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def require_database(container, database, role='query'):
    if role not in ('query', 'source', 'restore'):
        raise ValueError('unsupported backup database role')
    policy = _ACTIVE.get()
    if policy is None:
        allowed = ('m4_validation',) if role == 'source' else ('m4_restore_validation',) if role == 'restore' else ('m4_validation', 'm4_restore_validation')
        if database not in allowed:
            raise ValueError('only disposable validation databases allowed; deployment requires explicit operator policy')
        return
    expected = (policy.source,) if role == 'source' else (policy.restore,) if role == 'restore' else (policy.source, policy.restore)
    if container != policy.container or database not in expected:
        raise ValueError('database endpoint outside explicit deployment policy')
