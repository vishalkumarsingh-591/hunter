from __future__ import annotations

import os
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class SystemResources:
    cpu_count: int
    ram_gb: int


def _detect_ram_gb() -> int:
    if sys.platform == "win32":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):  # type: ignore[attr-defined]
                return max(1, int(stat.ullTotalPhys / (1024**3)))
        except Exception:  # noqa: BLE001
            pass
    else:
        try:
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return max(1, kb // (1024 * 1024))
        except OSError:
            pass
    return 8


def detect_system_resources() -> SystemResources:
    cpus = os.cpu_count() or 1
    return SystemResources(cpu_count=cpus, ram_gb=_detect_ram_gb())
