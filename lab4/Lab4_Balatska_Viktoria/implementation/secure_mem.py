import ctypes
import platform


def _get_libc():
    sysname = platform.system()
    if sysname == "Darwin":
        return ctypes.CDLL("libSystem.B.dylib")
    if sysname == "Linux":
        return ctypes.CDLL("libc.so.6")
    raise OSError("Unsupported OS (only Linux/macOS supported)")


def mlock_memory(buf):
    libc = _get_libc()
    addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
    if libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf))) != 0:
        raise OSError("mlock() failed — try sudo or adjust limits")


def munlock_memory(buf):
    libc = _get_libc()
    addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
    libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))


def secure_zero(buf):
    for i in range(len(buf)):
        buf[i] = 0
