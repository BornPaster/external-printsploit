import ctypes
import ctypes.wintypes
import struct
import sys

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
TOKEN_ALL_ACCESS = 0xF01FF
SE_PRIVILEGE_ENABLED = 0x2
DUPLICATE_SAME_ACCESS = 0x2
TH32CS_SNAPPROCESS = 0x2
ERROR_NOT_ALL_ASSIGNED = 1300
TP_DIRECT_SIZE = 72
TP_DIRECT_CALLBACK_OFFSET = 56

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
advapi32 = ctypes.windll.advapi32

kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

def current_process():
    return ctypes.c_void_p(kernel32.GetCurrentProcess())


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_ulong)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


def set_privilege(privilege, attributes):
    token = ctypes.wintypes.HANDLE()
    if not advapi32.OpenProcessToken(current_process(), TOKEN_ALL_ACCESS, ctypes.byref(token)):
        return False
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, privilege, ctypes.byref(luid)):
        kernel32.CloseHandle(token)
        return False
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = attributes
    result = advapi32.AdjustTokenPrivileges(
        token, False, ctypes.byref(tp), ctypes.sizeof(TOKEN_PRIVILEGES), None, None
    )
    err = kernel32.GetLastError()
    kernel32.CloseHandle(token)
    return bool(result) and err != ERROR_NOT_ALL_ASSIGNED


def find_process_pid(target_name):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == -1:
        return 0
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    pid = 0
    if kernel32.Process32FirstW(snap, ctypes.byref(entry)):
        while True:
            if entry.szExeFile.lower() == target_name.lower():
                pid = entry.th32ProcessID
                break
            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    kernel32.CloseHandle(ctypes.c_void_p(snap))
    return pid


RBX_PRINT   = 0
RBX_INFO    = 1
RBX_WARNING = 2
RBX_ERROR   = 3

_RBX_LEVEL_MAP = {
    RBX_PRINT:   0,
    RBX_INFO:    1,
    RBX_WARNING: 2,
    RBX_ERROR:   3,
}

def build_shellcode(message, rbx_level):
    gmha_addr = ctypes.cast(kernel32.GetModuleHandleA, ctypes.c_void_p).value
    raw_level = _RBX_LEVEL_MAP.get(rbx_level, 1)
    msg_bytes = message.encode("utf-8") + b'\x00'
    sc = bytearray()
    sc += b'\x48\x83\xEC\x28'
    sc += b'\x33\xC9'
    sc += b'\x48\xB8' + struct.pack('<Q', gmha_addr)
    sc += b'\xFF\xD0'
    sc += b'\x48\x05' + struct.pack('<I', 0x1DCD0B0) # replace 0x1DCD0B0 with updated print offset
    sc += b'\x49\x89\xC2'
    sc += b'\xB9' + struct.pack('<I', raw_level)
    sc += b'\x48\x8D\x15\x08\x00\x00\x00'
    sc += b'\x41\xFF\xD2'
    sc += b'\x48\x83\xC4\x28'
    sc += b'\xC3'
    sc += msg_bytes
    return bytes(sc)


def find_io_completion_handle(process):
    type_info_buf = (ctypes.c_ubyte * 10000)()
    for i in range(4, 8192, 4):
        dup_handle = ctypes.wintypes.HANDLE()
        if kernel32.DuplicateHandle(
            ctypes.c_void_p(process), ctypes.c_void_p(i),
            current_process(), ctypes.byref(dup_handle),
            0, False, DUPLICATE_SAME_ACCESS
        ):
            status = ntdll.NtQueryObject(dup_handle, 2, type_info_buf, 10000, None)
            if status >= 0:
                type_info_base = ctypes.addressof(type_info_buf)
                buf_ptr = struct.unpack_from('<Q', type_info_buf, 8)[0]
                length = struct.unpack_from('<H', type_info_buf, 0)[0]
                if buf_ptr and length >= 2:
                    name_offset = buf_ptr - type_info_base
                    if 0 <= name_offset <= 10000 - length:
                        try:
                            name = bytes(type_info_buf[name_offset:name_offset + length]).decode('utf-16-le')
                            if name == "IoCompletion":
                                return dup_handle.value
                        except Exception:
                            pass
            kernel32.CloseHandle(dup_handle)
    return None


def find_code_cave(process):
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    while True:
        if not kernel32.VirtualQueryEx(ctypes.c_void_p(process), ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE and size >= TP_DIRECT_SIZE:
            chunk_size = 4096
            off = 0
            while off <= size - TP_DIRECT_SIZE:
                read_size = min(chunk_size, size - off)
                buf = (ctypes.c_ubyte * read_size)()
                bytes_read = ctypes.c_size_t(0)
                if not kernel32.ReadProcessMemory(
                    ctypes.c_void_p(process), ctypes.c_void_p(base + off),
                    buf, read_size, ctypes.byref(bytes_read)
                ):
                    break
                data = bytes(buf[:bytes_read.value])
                for j in range(len(data) - TP_DIRECT_SIZE + 1):
                    if data[j:j + TP_DIRECT_SIZE] == b'\x00' * TP_DIRECT_SIZE:
                        return base + off + j
                off += chunk_size
        next_addr = base + size
        if next_addr <= addr or next_addr >= 0x7FFFFFFFFFFF:
            break
        addr = next_addr
    return None


def inject(process, shellcode_addr):
    completion_handle = find_io_completion_handle(process)
    if not completion_handle:
        print("failed to find IoCompletion handle")
        return False

    cave_addr = find_code_cave(process)
    if not cave_addr:
        print("failed to find suitable codecave in roblox")
        kernel32.CloseHandle(ctypes.c_void_p(completion_handle))
        return False

    tp_direct = bytearray(TP_DIRECT_SIZE)
    struct.pack_into('<Q', tp_direct, TP_DIRECT_CALLBACK_OFFSET, shellcode_addr)

    bytes_written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(
        ctypes.c_void_p(process), ctypes.c_void_p(cave_addr),
        (ctypes.c_byte * TP_DIRECT_SIZE)(*tp_direct),
        TP_DIRECT_SIZE, ctypes.byref(bytes_written)
    ):
        err = kernel32.GetLastError()
        print(f"failed to write TP_DIRECT structure to roblox: error 0x{err:X}")
        kernel32.CloseHandle(ctypes.c_void_p(completion_handle))
        return False

    status = ntdll.ZwSetIoCompletion(
        ctypes.c_void_p(completion_handle),
        ctypes.c_void_p(cave_addr),
        None,
        ctypes.c_long(0),
        ctypes.c_size_t(0)
    )
    if status < 0:
        print(f"failed to set IO completion, status 0x{status & 0xFFFFFFFF:X}")
        kernel32.CloseHandle(ctypes.c_void_p(completion_handle))
        return False

    kernel32.CloseHandle(ctypes.c_void_p(completion_handle))
    return True


def printsploit(message, level=RBX_PRINT):
    if not set_privilege("SeDebugPrivilege", SE_PRIVILEGE_ENABLED):
        print("privilege elevation failed. make sure to run as admin")
        return 1

    pid = find_process_pid("RobloxPlayerBeta.exe")
    if not pid:
        print("target process not found")
        return 1

    process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process:
        print("process access denied")
        return 1

    shellcode = build_shellcode(message, level)
    shellcode_remote = kernel32.VirtualAllocEx(
        ctypes.c_void_p(process), None, len(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    )
    if not shellcode_remote:
        print("failed to allocate shellcode memory")
        kernel32.CloseHandle(ctypes.c_void_p(process))
        return 1

    bytes_written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(
        ctypes.c_void_p(process), ctypes.c_void_p(shellcode_remote),
        (ctypes.c_byte * len(shellcode))(*shellcode),
        len(shellcode), ctypes.byref(bytes_written)
    ):
        print("failed to write shellcode")
        kernel32.VirtualFreeEx(ctypes.c_void_p(process), ctypes.c_void_p(shellcode_remote), 0, MEM_RELEASE)
        kernel32.CloseHandle(ctypes.c_void_p(process))
        return 1

    if not inject(process, shellcode_remote):
        print("injection failed")
        kernel32.VirtualFreeEx(ctypes.c_void_p(process), ctypes.c_void_p(shellcode_remote), 0, MEM_RELEASE)
        kernel32.CloseHandle(ctypes.c_void_p(process))
        return 1

    kernel32.CloseHandle(ctypes.c_void_p(process))
    print(f"injected successfully: {message}")
    return 0


printsploit("testing fire, normal print")
printsploit("testing fire, error print", RBX_ERROR)
printsploit("testing fire, info print", RBX_INFO)
printsploit("testing fire, warning print", RBX_WARNING)
