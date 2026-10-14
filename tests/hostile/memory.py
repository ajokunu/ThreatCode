"""The peak memory of the running process, on every platform the suite runs on.

``resource`` is a Unix module: it does not exist on Windows, where the same number is the peak
working set that ``GetProcessMemoryInfo`` reports.
"""

from __future__ import annotations

import sys


def peak_memory_mb() -> float:
    """The most resident memory this process has used, in megabytes; 0.0 when it cannot be read."""
    try:
        import resource
    except ImportError:  # Windows
        return _windows_peak_mb()
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kilobytes, macOS bytes
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


def _windows_peak_mb() -> float:
    """``PeakWorkingSetSize`` of this process, or 0.0 when the call fails or this is not Windows."""
    if sys.platform != "win32":
        return 0.0
    try:
        import ctypes
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            """``PROCESS_MEMORY_COUNTERS`` of psapi.h."""

            _fields_ = (
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            )

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.argtypes = ()
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        process = kernel32.GetCurrentProcess()
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(ProcessMemoryCounters)
        # Windows 7 and later export the call from kernel32 as K32GetProcessMemoryInfo, and
        # psapi.dll has always exported it as GetProcessMemoryInfo
        for library, name in (
            ("kernel32", "K32GetProcessMemoryInfo"),
            ("psapi", "GetProcessMemoryInfo"),
        ):
            try:
                function = getattr(ctypes.WinDLL(library, use_last_error=True), name)
            except (OSError, AttributeError):
                continue
            function.argtypes = (
                wintypes.HANDLE,
                ctypes.POINTER(ProcessMemoryCounters),
                wintypes.DWORD,
            )
            function.restype = wintypes.BOOL
            if function(process, ctypes.byref(counters), counters.cb):
                return counters.PeakWorkingSetSize / (1024 * 1024)
        return 0.0
    except Exception:  # noqa: BLE001 - a probe that fails must not fail the scan it measures
        return 0.0
