import sys
import ctypes
import platform
import resource


def disable_core_dumps():
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except Exception:
        return False


def linux_disable_ptrace():
    if platform.system() != "Linux":
        return False
    try:
        libc = ctypes.CDLL("libc.so.6")
        PR_SET_DUMPABLE = 4
        res = libc.prctl(PR_SET_DUMPABLE, ctypes.c_ulong(0), 0, 0, 0)
        return res == 0
    except Exception:
        return False


def is_debugger_attached():
    return sys.gettrace() is not None


def apply_process_guards(verbose_print=print):
    ok_core = disable_core_dumps()
    ok_ptrace = linux_disable_ptrace()
    if verbose_print:
        verbose_print(f"[*] Core dumps disabled: {ok_core}")
        if platform.system() == "Linux":
            verbose_print(f"[*] Linux ptrace disabled: {ok_ptrace}")
        if is_debugger_attached():
            verbose_print("[!] Debugger detected (sys.gettrace() is not None)")
