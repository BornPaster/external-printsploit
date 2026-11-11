import ctypes
import ctypes.wintypes as wt
import re
import struct
import json
import os
import time

kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll.dll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
psapi = ctypes.WinDLL("psapi.dll", use_last_error=True)


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


def _proto(func, argtypes, restype):
    func.argtypes = argtypes
    func.restype = restype


_proto(kernel32.OpenProcess, [wt.DWORD, wt.BOOL, wt.DWORD], ctypes.c_void_p)
_proto(kernel32.CloseHandle, [ctypes.c_void_p], wt.BOOL)
_proto(kernel32.GetCurrentProcess, [], ctypes.c_void_p)
_proto(kernel32.GetModuleHandleA, [wt.LPCWSTR], ctypes.c_void_p)
_proto(kernel32.GetLastError, [], wt.DWORD)
_proto(kernel32.VirtualAllocEx, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD], ctypes.c_void_p)
_proto(kernel32.VirtualFreeEx, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD], wt.BOOL)
_proto(kernel32.WriteProcessMemory, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)], wt.BOOL)
_proto(kernel32.VirtualQueryEx, [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t], ctypes.c_size_t)
_proto(kernel32.CreateToolhelp32Snapshot, [wt.DWORD, wt.DWORD], ctypes.c_void_p)
_proto(kernel32.Process32FirstW, [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)], wt.BOOL)
_proto(kernel32.Process32NextW, [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)], wt.BOOL)
_proto(kernel32.DuplicateHandle, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL, wt.DWORD], wt.BOOL)
_proto(ntdll.NtReadVirtualMemory, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)], ctypes.c_long)
_proto(ntdll.NtQueryObject, [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, wt.ULONG, ctypes.POINTER(wt.ULONG)], ctypes.c_long)
_proto(ntdll.ZwSetIoCompletion, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long, ctypes.c_size_t], ctypes.c_long)
_proto(advapi32.OpenProcessToken, [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.HANDLE)], wt.BOOL)
_proto(advapi32.LookupPrivilegeValueW, [wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(LUID)], wt.BOOL)
_proto(advapi32.AdjustTokenPrivileges, [ctypes.c_void_p, wt.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wt.DWORD, ctypes.c_void_p, ctypes.c_void_p], wt.BOOL)
_proto(psapi.EnumProcessModulesEx, [ctypes.c_void_p, ctypes.POINTER(wt.HMODULE), wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD], wt.BOOL)
_proto(psapi.GetModuleFileNameExW, [ctypes.c_void_p, wt.HMODULE, wt.LPWSTR, wt.DWORD], wt.DWORD)
_proto(psapi.GetModuleInformation, [ctypes.c_void_p, wt.HMODULE, ctypes.POINTER(MODULEINFO), wt.DWORD], wt.BOOL)


class dumper:
    lea_pattern = re.compile(rb"[\x48-\x4F]\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D](.{4})", re.DOTALL)

    def __init__(self, process: "printsploit"):
        self.process = process

    def _anchor_hits(self, image: bytearray) -> list:
        hits = []
        pos = 0
        while True:
            i = image.find(b"Current identity is %d", pos)
            if i < 0:
                break
            if image[i + len(b"Current identity is %d")] == 0:
                hits.append(i)
            pos = i + 1
        return hits

    def _lea_sites(self, image: bytearray) -> dict:
        sites = {}
        for m in self.lea_pattern.finditer(image):
            disp = int.from_bytes(m.group(1), "little", signed=True)
            target = m.start() + 7 + disp
            if target >= 0:
                sites.setdefault(target, []).append(m.start())
        return sites

    def _next_call(self, image: bytearray, pos: int) -> int:
        i = image.find(b"\xE8", pos, pos + 0x20)
        if i < 0:
            return 0
        rel = int.from_bytes(image[i + 1 : i + 5], "little", signed=True)
        return i + 5 + rel

    def _count_callers(self, image: bytearray, target: int) -> int:
        count = 0
        pos = 0
        size = len(image)
        while pos < size:
            i = image.find(b"\xE8", pos)
            if i < 0 or i + 5 > size:
                break
            rel = int.from_bytes(image[i + 1 : i + 5], "little", signed=True)
            if i + 5 + rel == target:
                count += 1
            pos = i + 1
        return count

    def dump(self) -> int:
        base, size = self.process.module("RobloxPlayerBeta.exe")
        image = self.process.snapshot(base, size)
        hits = self._anchor_hits(image)
        if not hits:
            raise RuntimeError("anchor string not found")
        sites = self._lea_sites(image)
        votes = {}
        for s in hits:
            for site in sites.get(s, ()):
                call = self._next_call(image, site + 7)
                if call:
                    votes[call] = votes.get(call, 0) + 1
        if not votes:
            raise RuntimeError("no call site references the anchor string")
        target, _ = max(votes.items(), key=lambda kv: kv[1])
        if self._count_callers(image, target) < 8:
            raise RuntimeError("candidate rejected, too few callers")
        return target


class printsploit:
    tp_direct_size = 72
    cache_file = "offsetcache.json"

    def __init__(self):
        self.handle = None
        self.print_rva = None
        self.io_port_handle = None

    def enable_debug_privilege(self) -> bool:
        token = wt.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0xF01FF, ctypes.byref(token)):
            return False
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            kernel32.CloseHandle(token)
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = 0x2
        result = advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), ctypes.sizeof(TOKEN_PRIVILEGES), None, None)
        partial = kernel32.GetLastError() == 1300
        kernel32.CloseHandle(token)
        return bool(result) and not partial

    def find_process_id(self, image_name: str) -> int:
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

    def read(self, address: int, size: int) -> bytes:
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        status = ntdll.NtReadVirtualMemory(self.handle, ctypes.c_void_p(address), buf, size, ctypes.byref(got))
        if status != 0 or got.value == 0:
            return b""
        return buf.raw[: got.value]

    def write(self, address: int, data: bytes) -> bool:
        written = ctypes.c_size_t(0)
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        return bool(kernel32.WriteProcessMemory(self.handle, ctypes.c_void_p(address), buf, len(data), ctypes.byref(written)))

    def alloc(self, size: int) -> int:
        addr = kernel32.VirtualAllocEx(self.handle, None, size, 0x3000, 0x40)
        if not addr:
            raise RuntimeError("failed to allocate shellcode memory")
        return addr

    def free(self, address: int):
        kernel32.VirtualFreeEx(self.handle, ctypes.c_void_p(address), 0, 0x8000)

    def module(self, image_name: str) -> tuple:
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
                return info.lpBaseOfDll, info.SizeOfImage
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

    def build_shellcode(self, message: str, level: int, print_rva: int) -> bytes:
        get_module_handle = ctypes.cast(kernel32.GetModuleHandleA, ctypes.c_void_p).value
        payload = message.encode("utf-8") + b"\x00"
        sc = bytearray()
        sc += b"\x48\x83\xEC\x28"
        sc += b"\x33\xC9"
        sc += b"\x48\xB8" + struct.pack("<Q", get_module_handle)
        sc += b"\xFF\xD0"
        sc += b"\x48\x05" + struct.pack("<I", print_rva)
        sc += b"\x49\x89\xC2"
        sc += b"\xB9" + struct.pack("<I", int(level))
        sc += b"\x48\x8D\x15\x08\x00\x00\x00"
        sc += b"\x41\xFF\xD2"
        sc += b"\x48\x83\xC4\x28"
        sc += b"\xC3"
        sc += payload
        return bytes(sc)

    def find_io_completion_port(self) -> int:
        if self.io_port_handle:
            return self.io_port_handle

        type_info = (ctypes.c_ubyte * 10000)()
        for candidate in range(4, 8192, 4):
            dup = wt.HANDLE()
            if not kernel32.DuplicateHandle(self.handle, ctypes.c_void_p(candidate),
                                            kernel32.GetCurrentProcess(), ctypes.byref(dup),
                                            0, False, 0x2):
                continue
            status = ntdll.NtQueryObject(dup, 2, type_info, 10000, None)
            if status >= 0:
                base = ctypes.addressof(type_info)
                name_ptr = struct.unpack_from("<Q", type_info, 8)[0]
                length = struct.unpack_from("<H", type_info, 0)[0]
                if name_ptr and length >= 2:
                    offset = name_ptr - base
                    if 0 <= offset <= 10000 - length:
                        try:
                            name = bytes(type_info[offset : offset + length]).decode("utf-16-le")
                            if name == "IoCompletion":
                                return dup.value
                        except UnicodeDecodeError:
                            pass
            kernel32.CloseHandle(dup)
        raise RuntimeError("failed to find IoCompletion handle")



    def find_code_cave(self) -> int:
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        while True:
            if not kernel32.VirtualQueryEx(self.handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize
            if mbi.State == 0x1000 and mbi.Protect == 0x04 and size >= self.tp_direct_size:
                zeros = b"\x00" * self.tp_direct_size
                off = 0
                while off <= size - self.tp_direct_size:
                    n = min(4096, size - off)
                    data = self.read(base + off, n)
                    if not data:
                        break
                    j = data.find(zeros)
                    if j >= 0 and j + self.tp_direct_size <= len(data):
                        return base + off + j
                    off += 4096
            nxt = base + size
            if nxt <= addr or nxt >= 0x7FFFFFFFFFFF:
                break
            addr = nxt
        raise RuntimeError("failed to find suitable code cave in roblox")

    def inject(self, shellcode_addr: int):
        port = self.find_io_completion_port()
        try:
            cave = self.find_code_cave()
            tp_direct = bytearray(self.tp_direct_size)
            struct.pack_into("<Q", tp_direct, 56, shellcode_addr)
            if not self.write(cave, bytes(tp_direct)):
                raise RuntimeError("failed to write TP_DIRECT structure to roblox")
            status = ntdll.ZwSetIoCompletion(ctypes.c_void_p(port), ctypes.c_void_p(cave), None, 0, 0)
            if status < 0:
                raise RuntimeError(f"failed to set IO completion, status 0x{status & 0xFFFFFFFF:X}")
        finally:
            if not self.io_port_handle:
                kernel32.CloseHandle(ctypes.c_void_p(port))

    def resolve_print_rva(self) -> int:
        if self.print_rva is not None:
            return self.print_rva

        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                    self.print_rva = cache.get("print_rva")
                    if self.print_rva:
                        print(f"loaded cached print offset: 0x{self.print_rva:x}")
                    if time.time() - os.path.getmtime(self.cache_file) < 7200:
                        return self.print_rva
            except (json.JSONDecodeError, IOError):
                print("failed to read cache file, ignoring...")

        self.print_rva = dumper(self).dump()
        print(f"print offset resolved: 0x{self.print_rva:x}")
        
        try:
            with open(self.cache_file, 'w') as f:
                json.dump({"print_rva": self.print_rva}, f)
            print(f"saved print offset to {self.cache_file}")
        except IOError as e:
            print(f"failed to write cache file{e}")
        return self.print_rva

    def send(self, message: str, level: int = 0):
        try:
            self.enable_debug_privilege()
            pid = self.find_process_id("RobloxPlayerBeta.exe")
            if not pid:
                raise RuntimeError("target process not found")
            if not self.handle:
                self.handle = kernel32.OpenProcess(0x1F0FFF, False, pid)
                if not self.handle:
                    raise RuntimeError("process access denied (try running as admin)")
            try:
                rva = self.resolve_print_rva()
                shellcode = self.build_shellcode(message, level, rva)
                remote = self.alloc(len(shellcode))
                try:
                    if not self.write(remote, shellcode):
                        raise RuntimeError("failed to write shellcode")
                    self.inject(remote)
                except Exception:
                    self.free(remote)
                    raise
            finally:
                pass
        except RuntimeError as e:
            print(f"[!] {e}")
            if "no call site" in str(e) or "candidate rejected" in str(e):
                if os.path.exists(self.cache_file):
                    os.remove(self.cache_file)
                    print("likely an invalidated or outdated cache file, removing it...")
            return
        print(f"injected successfully: {message}")


if __name__ == "__main__":
    sploit = printsploit()
    sploit.send("testing fire, normal print")
    sploit.send("testing fire, error print", 3)
    sploit.send("testing fire, info print", 1)
    sploit.send("testing fire, warning print", 2)
