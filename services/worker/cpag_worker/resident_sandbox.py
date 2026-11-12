"""Linux compute privilege boundary; failure to install it prevents execution."""
import ctypes
import errno
import os
import resource
import sys


def enter(config):
    if not sys.platform.startswith('linux') or os.getuid() != 0:
        raise RuntimeError('resident sandbox requires Linux root supervisor')
    # Load before dropping privileges. No fallback to an unrestricted child.
    seccomp = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    libc = ctypes.CDLL(None, use_errno=True)
    os.setgroups([])
    os.setgid(65532)
    os.setuid(65532)
    if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'no_new_privs')
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    context = seccomp.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError('seccomp allocation failed')
    try:
        # Offline core needs no sockets. Deny bypasses via io_uring and prevent
        # detached descendants from escaping the guardian process group.
        for name in ('socket', 'socketpair', 'connect', 'io_uring_setup',
                     'setsid', 'setpgid', 'unshare', 'setns', 'mount',
                     'ptrace', 'process_vm_readv', 'process_vm_writev', 'bpf'):
            number = seccomp.seccomp_syscall_resolve_name(name.encode())
            if number >= 0 and seccomp.seccomp_rule_add(context, 0x50000 | errno.EPERM, number, 0):
                raise RuntimeError('seccomp rule failed')
        if seccomp.seccomp_load(context):
            raise RuntimeError('seccomp load failed')
    finally:
        seccomp.seccomp_release(context)
    os.umask(0o077)
    os.chdir(config['cwd'])
