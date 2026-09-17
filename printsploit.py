import ctypes
import ctypes.wintypes as wt
import re
import struct
from dataclasses import dataclass

kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll.dll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
psapi = ctypes.WinDLL("psapi.dll", use_last_error=True)

ANCHOR = b"Current identity is %d"

RBX_PRINT = 0
RBX_INFO = 1
RBX_WARNING = 2
RBX_ERROR = 3


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_ulong)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class PROCESSENTRY32W(ctypes.Structure):
    _pack_ = 4
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_void_p),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_wchar * 260),
        ("_stride", ctypes.c_ulong),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("_pad2", wt.DWORD),
    ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wt.DWORD), ("EntryPoint", ctypes.c_void_p)]


kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.GetCurrentProcess.restype = ctypes.c_void_p
kernel32.GetModuleHandleA.argtypes = [wt.LPCWSTR]
kernel32.GetModuleHandleA.restype = ctypes.c_void_p
kernel32.GetLastError.restype = wt.DWORD
kernel32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]
kernel32.VirtualFreeEx.restype = wt.BOOL
kernel32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wt.BOOL
kernel32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wt.BOOL
kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wt.BOOL
ntdll.NtReadVirtualMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ntdll.NtReadVirtualMemory.restype = ctypes.c_long
ntdll.NtQueryObject.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, wt.ULONG, ctypes.POINTER(wt.ULONG)]
ntdll.NtQueryObject.restype = ctypes.c_long
ntdll.ZwSetIoCompletion.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long, ctypes.c_size_t]
ntdll.ZwSetIoCompletion.restype = ctypes.c_long
advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
advapi32.OpenProcessToken.restype = wt.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.LookupPrivilegeValueW.restype = wt.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [ctypes.c_void_p, wt.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wt.DWORD, ctypes.c_void_p, ctypes.c_void_p]
advapi32.AdjustTokenPrivileges.restype = wt.BOOL
kernel32.DuplicateHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.DuplicateHandle.restype = wt.BOOL
psapi.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.HMODULE), wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD]
psapi.EnumProcessModulesEx.restype = wt.BOOL
psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, wt.HMODULE, wt.LPWSTR, wt.DWORD]
psapi.GetModuleFileNameExW.restype = wt.DWORD
psapi.GetModuleInformation.argtypes = [ctypes.c_void_p, wt.HMODULE, ctypes.POINTER(MODULEINFO), wt.DWORD]
psapi.GetModuleInformation.restype = wt.BOOL


@dataclass
class Module:
    base: int
    size: int


class System:
    @staticmethod
    def enable_privilege(name: str) -> bool:
        token = wt.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0xF01FF, ctypes.byref(token)):
            return False
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            kernel32.CloseHandle(token)
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = 0x2
        result = advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), ctypes.sizeof(TOKEN_PRIVILEGES), None, None)
        failed = kernel32.GetLastError() == 1300
        kernel32.CloseHandle(token)
        return bool(result) and not failed

    @staticmethod
    def find_pid(image_name: str) -> int:
        snap = kernel32.CreateToolhelp32Snapshot(0x2, 0)
        if not snap or snap == -1:
            return 0
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        pid = 0
        if kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.lower() == image_name.lower():
                    pid = entry.th32ProcessID
                    break
                if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                    break
        kernel32.CloseHandle(snap)
        return pid


class TargetProcess:
    def __init__(self, pid: int):
        self.handle = kernel32.OpenProcess(0x1F0FFF, False, pid)
        if not self.handle:
            raise RuntimeError("process access denied (try running as admin)")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        kernel32.CloseHandle(self.handle)

    def read(self, address: int, size: int) -> bytes:
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        status = ntdll.NtReadVirtualMemory(self.handle, ctypes.c_void_p(address), buf, size, ctypes.byref(got))
        if status != 0 or got.value == 0:
            return b""
        return buf.raw[: got.value]

    def module(self, image_name: str) -> Module:
        needed = wt.DWORD()
        psapi.EnumProcessModulesEx(self.handle, None, 0, ctypes.byref(needed), 0x03)
        count = needed.value // ctypes.sizeof(wt.HMODULE)
        modules = (wt.HMODULE * count)()
        psapi.EnumProcessModulesEx(self.handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 0x03)
        for hmod in modules:
            name = ctypes.create_unicode_buffer(512)
            psapi.GetModuleFileNameExW(self.handle, hmod, name, 512)
            if name.value.lower().endswith(image_name.lower()):
                info = MODULEINFO()
                psapi.GetModuleInformation(self.handle, hmod, ctypes.byref(info), ctypes.sizeof(info))
                return Module(info.lpBaseOfDll, info.SizeOfImage)
        raise RuntimeError(f"{image_name} not found in target process")

    def snapshot(self, base: int, size: int) -> bytearray:
        buf = bytearray(size)
        view = memoryview(buf)
        mbi = MEMORY_BASIC_INFORMATION()
        cur, end = base, base + size
        while cur < end:
            if not kernel32.VirtualQueryEx(self.handle, ctypes.c_void_p(cur), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            rstart = mbi.BaseAddress or 0
            rend = min(rstart + mbi.RegionSize, end)
            if mbi.State == 0x1000 and not (mbi.Protect & 0x100) and not (mbi.Protect & 0x01):
                local = rstart
                while local < rend:
                    n = min(0x1000000, rend - local)
                    data = self.read(local, n)
                    if len(data) == n:
                        off = local - base
                        view[off : off + n] = data
                        local += n
                    else:
                        local += 0x1000
            cur = rend
        view.release()
        return buf

    def alloc(self, size: int) -> int:
        addr = kernel32.VirtualAllocEx(self.handle, None, size, 0x3000, 0x40)
        if not addr:
            raise RuntimeError("failed to allocate shellcode memory")
        return addr

    def write(self, address: int, data: bytes) -> bool:
        written = ctypes.c_size_t(0)
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        return bool(kernel32.WriteProcessMemory(self.handle, ctypes.c_void_p(address), buf, len(data), ctypes.byref(written)))

    def free(self, address: int):
        kernel32.VirtualFreeEx(self.handle, ctypes.c_void_p(address), 0, 0x8000)


class PrintScanner:
    LEA = re.compile(rb"[\x48-\x4F]\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D](.{4})", re.DOTALL)

    def __init__(self, buffer: bytearray):
        self.buffer = buffer

    def _string_hits(self) -> list:
        hits = []
        find = self.buffer.find
        pos = 0
        while True:
            i = find(ANCHOR, pos)
            if i < 0:
                break
            if self.buffer[i + len(ANCHOR)] == 0:
                hits.append(i)
            pos = i + 1
        return hits

    def _lea_map(self) -> dict:
        mapping = {}
        for m in self.LEA.finditer(self.buffer):
            disp = int.from_bytes(m.group(1), "little", signed=True)
            target = m.start() + 7 + disp
            if target >= 0:
                mapping.setdefault(target, []).append(m.start())
        return mapping

    def _next_call(self, pos: int) -> int:
        i = self.buffer.find(b"\xE8", pos, pos + 0x20)
        if i < 0:
            return 0
        rel = int.from_bytes(self.buffer[i + 1 : i + 5], "little", signed=True)
        return i + 5 + rel

    def _count_callers(self, target: int) -> int:
        count = 0
        find = self.buffer.find
        pos = 0
        size = len(self.buffer)
        while pos < size:
            i = find(b"\xE8", pos)
            if i < 0 or i + 5 > size:
                break
            rel = int.from_bytes(self.buffer[i + 1 : i + 5], "little", signed=True)
            if i + 5 + rel == target:
                count += 1
            pos = i + 1
        return count

    def find(self) -> int:
        hits = self._string_hits()
        if not hits:
            raise RuntimeError("anchor string not found")
        leas = self._lea_map()
        votes = {}
        for s in hits:
            for site in leas.get(s, ()):
                call = self._next_call(site + 7)
                if call:
                    votes[call] = votes.get(call, 0) + 1
        if not votes:
            raise RuntimeError("no call site references the anchor string")
        target, _ = max(votes.items(), key=lambda kv: kv[1])
        if self._count_callers(target) < 8:
            raise RuntimeError("candidate rejected, too few callers")
        return target


class Shellcode:
    @staticmethod
    def build(message: str, level: int, print_rva: int) -> bytes:
        gmha = ctypes.cast(kernel32.GetModuleHandleA, ctypes.c_void_p).value
        msg = message.encode("utf-8") + b"\x00"
        sc = bytearray()
        sc += b"\x48\x83\xEC\x28"
        sc += b"\x33\xC9"
        sc += b"\x48\xB8" + struct.pack("<Q", gmha)
        sc += b"\xFF\xD0"
        sc += b"\x48\x05" + struct.pack("<I", print_rva)
        sc += b"\x49\x89\xC2"
        sc += b"\xB9" + struct.pack("<I", int(level))
        sc += b"\x48\x8D\x15\x08\x00\x00\x00"
        sc += b"\x41\xFF\xD2"
        sc += b"\x48\x83\xC4\x28"
        sc += b"\xC3"
        sc += msg
        return bytes(sc)


class Injector:
    TP_DIRECT_SIZE = 72
    CALLBACK_OFFSET = 56

    def __init__(self, process: TargetProcess):
        self.process = process

    def _find_io_completion(self) -> int:
        type_info_buf = (ctypes.c_ubyte * 10000)()
        for i in range(4, 8192, 4):
            dup_handle = wt.HANDLE()
            if kernel32.DuplicateHandle(self.process.handle, ctypes.c_void_p(i), kernel32.GetCurrentProcess(), ctypes.byref(dup_handle), 0, False, 0x2):
                status = ntdll.NtQueryObject(dup_handle, 2, type_info_buf, 10000, None)
                if status >= 0:
                    base = ctypes.addressof(type_info_buf)
                    name_ptr = struct.unpack_from("<Q", type_info_buf, 8)[0]
                    length = struct.unpack_from("<H", type_info_buf, 0)[0]
                    if name_ptr and length >= 2:
                        offset = name_ptr - base
                        if 0 <= offset <= 10000 - length:
                            try:
                                name = bytes(type_info_buf[offset : offset + length]).decode("utf-16-le")
                                if name == "IoCompletion":
                                    return dup_handle.value
                            except UnicodeDecodeError:
                                pass
                kernel32.CloseHandle(dup_handle)
        raise RuntimeError("failed to find IoCompletion handle")

    def _find_code_cave(self) -> int:
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        while True:
            if not kernel32.VirtualQueryEx(self.process.handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize
            if mbi.State == 0x1000 and mbi.Protect == 0x04 and size >= self.TP_DIRECT_SIZE:
                zeros = b"\x00" * self.TP_DIRECT_SIZE
                off = 0
                while off <= size - self.TP_DIRECT_SIZE:
                    n = min(4096, size - off)
                    data = self.process.read(base + off, n)
                    if not data:
                        break
                    j = data.find(zeros)
                    if j >= 0 and j + self.TP_DIRECT_SIZE <= len(data):
                        return base + off + j
                    off += 4096
            nxt = base + size
            if nxt <= addr or nxt >= 0x7FFFFFFFFFFF:
                break
            addr = nxt
        raise RuntimeError("failed to find suitable code cave in roblox")

    def inject(self, shellcode_addr: int):
        completion = self._find_io_completion()
        try:
            cave = self._find_code_cave()
            tp_direct = bytearray(self.TP_DIRECT_SIZE)
            struct.pack_into("<Q", tp_direct, self.CALLBACK_OFFSET, shellcode_addr)
            if not self.process.write(cave, bytes(tp_direct)):
                raise RuntimeError("failed to write TP_DIRECT structure to roblox")
            status = ntdll.ZwSetIoCompletion(ctypes.c_void_p(completion), ctypes.c_void_p(cave), None, 0, 0)
            if status < 0:
                raise RuntimeError(f"failed to set IO completion, status 0x{status & 0xFFFFFFFF:X}")
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(completion))


class PrintSploit:
    TARGET = "RobloxPlayerBeta.exe"

    def __init__(self):
        self._print_rva = None

    def _resolve_print_offset(self, process: TargetProcess) -> int:
        if self._print_rva is None:
            module = process.module(self.TARGET)
            buffer = process.snapshot(module.base, module.size)
            self._print_rva = PrintScanner(buffer).find()
            print(f"print offset resolved: 0x{self._print_rva:x}")
        return self._print_rva

    def send(self, message: str, level: int = RBX_PRINT):
        try:
            System.enable_privilege("SeDebugPrivilege")
            pid = System.find_pid(self.TARGET)
            if not pid:
                raise RuntimeError("target process not found")
            with TargetProcess(pid) as process:
                rva = self._resolve_print_offset(process)
                shellcode = Shellcode.build(message, level, rva)
                remote = process.alloc(len(shellcode))
                try:
                    if not process.write(remote, shellcode):
                        raise RuntimeError("failed to write shellcode")
                    Injector(process).inject(remote)
                except Exception:
                    process.free(remote)
                    raise
        except RuntimeError as e:
            print(f"[!] {e}")
            return
        print(f"injected successfully: {message}")


if __name__ == "__main__":
    sploit = PrintSploit()
    sploit.send("testing fire, normal print")
    sploit.send("testing fire, error print", RBX_ERROR)
    sploit.send("testing fire, info print", RBX_INFO)
    sploit.send("testing fire, warning print", RBX_WARNING)
