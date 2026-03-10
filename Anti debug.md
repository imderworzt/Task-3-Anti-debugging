1. Debug Flag
    - Một số chương trình dùng các cờ trong process/heap/system để kiểm tra có debugger hay không.

    - Các loại Debug Flag:
        - Dùng Win32/Native API: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, RtlQueryProcessHeapInformation, RtlQueryProcessDebugInformation, NtQuerySystemInformation.
        - Dò trực tiếp cấu trúc hệ thống: PEB (BeingDebugged, NtGlobalFlag), Heap Flags/ForceFlags, Heap Protection, KUSER_SHARED_DATA.

    - IsDebuggerPresent: trả về TRUE nếu process đang bị debug.
        - Code mẫu:
            ```
                if (IsDebuggerPresent()) {
                    exit(0);
                }
            ```

    - CheckRemoteDebuggerPresent: kiểm tra debugger attach từ process khác trên cùng máy.
        - Code mẫu:
            ```
                BOOL bDebuggerPresent = FALSE;
                if (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent)
                    && TRUE == bDebuggerPresent) {
                    exit(0);
                }
            ```

    - NtQueryInformationProcess: có nhiều class kiểm tra anti-debug.
        - ProcessDebugPort (7): giá trị -1 thường là có debugger.
        - ProcessDebugFlags (0x1F): giá trị 0 thường là có debugger.
        - ProcessDebugObjectHandle (0x1E): handle khác 0 thường là có debugger.
        - Code mẫu:
            ```
                DWORD value = 0, ret = 0;
                NtQueryInformationProcess(GetCurrentProcess(), 0x1F, &value, sizeof(value), &ret);
                if (value == 0) exit(0);
            ```

    - RtlQueryProcessHeapInformation(): đọc heap flags của process hiện tại.
        - Code mẫu:
            ```
                bool Check() {
                    auto p = ntdll::RtlCreateQueryDebugBuffer(0, FALSE);
                    if (!SUCCEEDED(ntdll::RtlQueryProcessHeapInformation((ntdll::PRTL_DEBUG_INFORMATION)p)))
                        return false;
                    ULONG flags = ((ntdll::PRTL_PROCESS_HEAPS)p->HeapInformation)->Heaps[0].Flags;
                    return flags & ~HEAP_GROWABLE;
                }
            ```

    - RtlQueryProcessDebugInformation(): đọc debug info (heap/heap blocks) để phát hiện cờ bất thường.
        - Code mẫu:
            ```
                bool Check() {
                    auto p = ntdll::RtlCreateQueryDebugBuffer(0, FALSE);
                    if (!SUCCEEDED(ntdll::RtlQueryProcessDebugInformation(GetCurrentProcessId(),
                        ntdll::PDI_HEAPS | ntdll::PDI_HEAP_BLOCKS, p)))
                        return false;
                    ULONG flags = ((ntdll::PRTL_PROCESS_HEAPS)p->HeapInformation)->Heaps[0].Flags;
                    return flags & ~HEAP_GROWABLE;
                }
            ```

    - NtQuerySystemInformation(SystemKernelDebuggerInformation = 0x23): kiểm tra kernel debugger.
        - Code mẫu:
            ```
                SYSTEM_KERNEL_DEBUGGER_INFORMATION s = {0};
                NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x23, &s, sizeof(s), NULL);
                if (s.DebuggerEnabled && !s.DebuggerNotPresent) exit(0);
            ```

    - PEB!BeingDebugged: kiểm tra byte BeingDebugged trong PEB.
        - Code mẫu:
            ```
                bool Check() {
                    PBYTE peb = (PBYTE)__readgsqword(0x60);
                    return *(PBYTE)(peb + 0x2) != 0;
                }
            ```

    - NtGlobalFlag: kiểm tra bit debug trong PEB->NtGlobalFlag.
        - Code mẫu:
            ```
                bool Check() {
                    PBYTE peb = (PBYTE)__readgsqword(0x60);
                    return *(DWORD*)(peb + 0xBC) & 0x70;
                }
            ```

    - Heap Flags/ForceFlags: debugger thường làm thay đổi các cờ heap.
        - Code mẫu:
            ```
                bool Check() {
                    PBYTE peb = (PBYTE)__readgsqword(0x60);
                    return *(DWORD*)(peb + 0x70) & 0x2;
                }
            ```

    - Heap Protection: kiểm tra pattern bảo vệ heap khi debug.
        - Code mẫu:
            ```
                bool Check() {
                    PBYTE peb = (PBYTE)__readgsqword(0x60);
                    return *(DWORD*)(peb + 0x74) & 0x100;
                }
            ```

    - KUSER_SHARED_DATA: kiểm tra các field liên quan kernel debug state.
        - Code mẫu:
            ```
                bool Check() {
                    return *(DWORD*)(0x7FFE0000 + 0x2C) != 0;
                }
            ```

2. Object Handles
    - Một số API dùng object handle sẽ có hành vi khác khi debugger can thiệp.

    - CreateFile(): thử mở độc quyền chính file đang chạy.
        - Code mẫu:
            ```
                bool Check() {
                    CHAR szFileName[MAX_PATH];
                    if (0 == GetModuleFileNameA(NULL, szFileName, sizeof(szFileName)))
                        return false;
                    return INVALID_HANDLE_VALUE == CreateFileA(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
                }
            ```

    - CloseHandle(): truyền invalid handle; dưới debugger có thể phát sinh EXCEPTION_INVALID_HANDLE.
        - Code mẫu:
            ```
                bool Check() {
                    __try {
                        CloseHandle((HANDLE)0xDEADBEEF);
                        return false;
                    }
                    __except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
                                ? EXCEPTION_EXECUTE_HANDLER
                                : EXCEPTION_CONTINUE_SEARCH) {
                        return true;
                    }
                }
            ```

    - LoadLibrary() + CreateFile(): một số debugger giữ handle file DLL/EXE debug event quá lâu.
        - Code mẫu:
            ```
                bool Check() {
                    CHAR szBuffer[] = {"C:\\Windows\\System32\\calc.exe"};
                    LoadLibraryA(szBuffer);
                    return INVALID_HANDLE_VALUE == CreateFileA(szBuffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
                }
            ```

    - NtQueryObject(): dò object type "DebugObject" để nhận biết hệ thống đang có debugger chạy.
        - Code mẫu:
            ```
                typedef struct _OBJECT_TYPE_INFORMATION
                {
                    UNICODE_STRING TypeName;
                    ULONG TotalNumberOfHandles;
                    ULONG TotalNumberOfObjects;
                } OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;
                
                typedef struct _OBJECT_ALL_INFORMATION
                {
                    ULONG NumberOfObjects;
                    OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
                } OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

                typedef NTSTATUS (WINAPI *TNtQueryObject)(
                    HANDLE                   Handle,
                    OBJECT_INFORMATION_CLASS ObjectInformationClass,
                    PVOID                    ObjectInformation,
                    ULONG                    ObjectInformationLength,
                    PULONG                   ReturnLength
                );
                
                enum { ObjectAllTypesInformation = 3 };
                
                #define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
                
                bool Check()
                {
                    bool bDebugged = false;
                    NTSTATUS status;
                    LPVOID pMem = nullptr;
                    ULONG dwMemSize;
                    POBJECT_ALL_INFORMATION pObjectAllInfo;
                    PBYTE pObjInfoLocation;
                    HMODULE hNtdll;
                    TNtQueryObject pfnNtQueryObject;
                
                hNtdll = LoadLibraryA("ntdll.dll");
                if (!hNtdll)
                    return false;
                    
                pfnNtQueryObject = (TNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
                if (!pfnNtQueryObject)
                    return false;
            
                status = pfnNtQueryObject(
                    NULL,
                    (OBJECT_INFORMATION_CLASS)ObjectAllTypesInformation,
                    &dwMemSize, sizeof(dwMemSize), &dwMemSize);
                if (STATUS_INFO_LENGTH_MISMATCH != status)
                    goto NtQueryObject_Cleanup;
            
                pMem = VirtualAlloc(NULL, dwMemSize, MEM_COMMIT, PAGE_READWRITE);
                if (!pMem)
                    goto NtQueryObject_Cleanup;
            
                status = pfnNtQueryObject(
                    (HANDLE)-1,
                    (OBJECT_INFORMATION_CLASS)ObjectAllTypesInformation,
                    pMem, dwMemSize, &dwMemSize);
                if (!SUCCEEDED(status))
                    goto NtQueryObject_Cleanup;
            
                pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMem;
                pObjInfoLocation = (PBYTE)pObjectAllInfo->ObjectTypeInformation;
                for(UINT i = 0; i < pObjectAllInfo->NumberOfObjects; i++)
                {
            
                    POBJECT_TYPE_INFORMATION pObjectTypeInfo =
                        (POBJECT_TYPE_INFORMATION)pObjInfoLocation;
            
                    if (wcscmp(L"DebugObject", pObjectTypeInfo->TypeName.Buffer) == 0)
                    {
                        if (pObjectTypeInfo->TotalNumberOfObjects > 0)
                            bDebugged = true;
                        break;
                    }
            
                    // Get the address of the current entries
                    // string so we can find the end
                    pObjInfoLocation = (PBYTE)pObjectTypeInfo->TypeName.Buffer;
            
                    // Add the size
                    pObjInfoLocation += pObjectTypeInfo->TypeName.Length;
            
                    // Skip the trailing null and alignment bytes
                    ULONG tmp = ((ULONG)pObjInfoLocation) & -4;
            
                    // Not pretty but it works
                    pObjInfoLocation = ((PBYTE)tmp) + sizeof(DWORD);
                }
            
                NtQueryObject_Cleanup:
                    if (pMem)
                        VirtualFree(pMem, 0, MEM_RELEASE);
            
                return bDebugged;
                }
            ```

3. Process Memory
    - Kiểm tra trực tiếp bộ nhớ process để tìm dấu vết breakpoints/patches.

    - Breakpoints:
        - Software Breakpoint (INT3): scan mã để tìm byte 0xCC.
            - Code mẫu:
                ```
                    bool HasInt3(PVOID pFunc, SIZE_T size = 0) {
                        PBYTE p = (PBYTE)pFunc;
                        for (SIZE_T i = 0;; ++i) {
                            if ((size > 0 && i >= size) || (size == 0 && p[i] == 0xC3)) break;
                            if (p[i] == 0xCC) return true;
                        }
                        return false;
                    }
                ```
        - Anti-Step-Over: đọc byte ở return address, phát hiện INT3 do debugger đặt khi Step Over.
            - Code mẫu:
                ```
                    #include <intrin.h>
                    #pragma intrinsic(_ReturnAddress)

                    bool CheckStepOverBp() {
                        PBYTE ret = (PBYTE)_ReturnAddress();
                        return (*ret == 0xCC);
                    }
                ```
        - Memory Breakpoint: lợi dụng guard-page behavior để phát hiện debugger.
            - Code mẫu:
                ```
                    bool CheckMemoryBreakpoint() {
                        SYSTEM_INFO si = {0};
                        GetSystemInfo(&si);
                        PBYTE page = (PBYTE)VirtualAlloc(NULL, si.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (!page) return false;
                        page[0] = 0xC3; // RET

                        DWORD oldProtect = 0;
                        if (!VirtualProtect(page, si.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProtect)) {
                            VirtualFree(page, 0, MEM_RELEASE);
                            return false;
                        }

                        bool debugged = false;
                        __try {
                            __asm {
                                mov eax, page
                                push mem_bp_debugged
                                jmp eax
                            }
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER) {
                            debugged = false;
                        }

                        VirtualFree(page, 0, MEM_RELEASE);
                        return debugged;

                    mem_bp_debugged:
                        VirtualFree(page, 0, MEM_RELEASE);
                        return true;
                    }
                ```
        - Hardware Breakpoint: đọc DR0..DR3 qua GetThreadContext.
            - Code mẫu:
                ```
                    bool CheckHardwareBp() {
                        CONTEXT ctx = {0};
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (!GetThreadContext(GetCurrentThread(), &ctx))
                            return false;
                        return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
                    }
                ```

    - Other memory checks:
        - NtQueryVirtualMemory (Working Set): nếu trang code bị COW do patch breakpoint thì Shared/ShareCount bất thường.
            - Code mẫu:
                ```
                    bool CheckWorkingSetAnomaly() {
                        // Ý tưởng: gọi NtQueryVirtualMemory(..., MemoryWorkingSetList, ...)
                        // tìm page chứa EIP/RIP hiện tại rồi kiểm tra Shared/ShareCount.
                        // Shared == 0 hoặc ShareCount == 0 => nghi ngờ bị patch breakpoint.
                        return suspicious;
                    }
                ```
        - Detecting function patch: so sánh bytes đầu của IsDebuggerPresent giữa process hiện tại và process khác.
            - Code mẫu:
                ```
                    bool CheckIsDebuggerPresentPatched() {
                        HMODULE hK32 = GetModuleHandleA("kernel32.dll");
                        if (!hK32) return false;
                        FARPROC f = GetProcAddress(hK32, "IsDebuggerPresent");
                        if (!f) return false;

                        DWORD localBytes = *(DWORD*)f;
                        // Ý tưởng: ReadProcessMemory cùng địa chỉ f từ process khác rồi so sánh.
                        DWORD remoteBytes = localBytes; // giá trị minh họa
                        return localBytes != remoteBytes;
                    }
                ```
        - Performing Code Checksums: CRC/hash hàm quan trọng định kỳ; thay đổi checksum => có patch/hook/breakpoint.
            - Code mẫu:
                ```
                    DWORD Checksum32(PBYTE p, SIZE_T n) {
                        DWORD s = 0;
                        for (SIZE_T i = 0; i < n; ++i) s = (s * 33) ^ p[i];
                        return s;
                    }

                    bool CheckCodeTamper(PVOID fn, SIZE_T fnSize, DWORD baseline) {
                        return Checksum32((PBYTE)fn, fnSize) != baseline;
                    }
                ```

4. Timing
    - Khi debug (đặc biệt step) độ trễ tăng, có thể đo để suy luận.

    - RDTSC
        - Code mẫu:
            ```
                bool CheckTimingRDTSC(unsigned long long threshold) {
                    unsigned __int64 start = __rdtsc();
                    // ... đoạn code cần đo
                    unsigned __int64 end = __rdtsc();
                    return (end - start) > threshold;
                }
            ```
    - GetLocalTime()
        - Code mẫu:
            ```
                bool CheckTimingLocalTime(ULONGLONG threshold100ns) {
                    SYSTEMTIME s1, s2;
                    FILETIME f1, f2;
                    ULARGE_INTEGER t1, t2;
                    GetLocalTime(&s1);
                    // ... đoạn code cần đo
                    GetLocalTime(&s2);
                    if (!SystemTimeToFileTime(&s1, &f1) || !SystemTimeToFileTime(&s2, &f2))
                        return false;
                    t1.LowPart = f1.dwLowDateTime; t1.HighPart = f1.dwHighDateTime;
                    t2.LowPart = f2.dwLowDateTime; t2.HighPart = f2.dwHighDateTime;
                    return (t2.QuadPart - t1.QuadPart) > threshold100ns;
                }
            ```
    - GetSystemTime()
        - Code mẫu:
            ```
                bool CheckTimingSystemTime(ULONGLONG threshold100ns) {
                    SYSTEMTIME s1, s2;
                    FILETIME f1, f2;
                    ULARGE_INTEGER t1, t2;
                    GetSystemTime(&s1);
                    // ... đoạn code cần đo
                    GetSystemTime(&s2);
                    if (!SystemTimeToFileTime(&s1, &f1) || !SystemTimeToFileTime(&s2, &f2))
                        return false;
                    t1.LowPart = f1.dwLowDateTime; t1.HighPart = f1.dwHighDateTime;
                    t2.LowPart = f2.dwLowDateTime; t2.HighPart = f2.dwHighDateTime;
                    return (t2.QuadPart - t1.QuadPart) > threshold100ns;
                }
            ```
    - GetTickCount()
        - Code mẫu:
            ```
                bool CheckTimingTickCount(DWORD thresholdMs) {
                    DWORD start = GetTickCount();
                    // ... đoạn code cần đo
                    DWORD end = GetTickCount();
                    return (end - start) > thresholdMs;
                }
            ```
    - QueryPerformanceCounter()
        - Code mẫu:
            ```
                bool CheckTimingQPC(double thresholdSec) {
                    LARGE_INTEGER freq, start, end;
                    QueryPerformanceFrequency(&freq);
                    QueryPerformanceCounter(&start);
                    // ... đoạn code cần đo
                    QueryPerformanceCounter(&end);
                    double elapsed = (double)(end.QuadPart - start.QuadPart) / (double)freq.QuadPart;
                    return elapsed > thresholdSec;
                }
            ```
    - timeGetTime()
        - Code mẫu:
            ```
                bool CheckTimingTimeGetTime(DWORD thresholdMs) {
                    DWORD start = timeGetTime();
                    // ... đoạn code cần đo
                    DWORD end = timeGetTime();
                    return (end - start) > thresholdMs;
                }
            ```

5. Exception
    - Cố tình tạo exception rồi quan sát debugger có “nuốt” exception hay không.

    - UnhandledExceptionFilter()
        - Code mẫu:
            ```
                LONG MyUnhandledFilter(PEXCEPTION_POINTERS p) {
                    p->ContextRecord->Eip += 3;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                bool Check() {
                    bool debugged = true;
                    SetUnhandledExceptionFilter(MyUnhandledFilter);
                    __asm {
                        int 3
                        jmp being_debugged
                    }
                    debugged = false;
                being_debugged:
                    return debugged;
                }
            ```

    - RaiseException(DBG_CONTROL_C/DBG_RIPEVENT)
        - Code mẫu:
            ```
                bool Check() {
                    __try {
                        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
                        return true;
                    }
                    __except (GetExceptionCode() == DBG_CONTROL_C
                              ? EXCEPTION_EXECUTE_HANDLER
                              : EXCEPTION_CONTINUE_SEARCH) {
                        return false;
                    }
                }
            ```

    - Hiding Control Flow with Exception Handlers (SEH/VEH): thường dùng để làm rối luồng thực thi trong phân tích tĩnh/động.

6. Assembly instructions
    - Dựa vào khác biệt hành vi debugger khi CPU thực thi instruction đặc biệt. Nhóm này thường phụ thuộc kiến trúc (x86/x64), compiler (MSVC/GCC), và cách debugger xử lý exception.

    - INT3 (0xCC hoặc `CD 03`)
        - Nguyên lý: tạo breakpoint exception (`EXCEPTION_BREAKPOINT`). Nếu debugger attach, exception có thể bị debugger bắt trước.
        - Dùng khi nào: check nhanh trong early-init.
        - Nhược điểm: dễ bị patch/bypass; nhiều debugger cho phép pass-through exception.
        - Code mẫu:
            ```
                bool CheckINT3_SEH() {
                    __try {
                        __asm { int 3 }
                        return true;   // debugger ăn exception, code vẫn chạy tiếp
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        return false;  // không debugger hoặc exception về app
                    }
                }
            ```

    - INT 2D
        - Nguyên lý: `int 0x2d` tạo breakpoint-like trap với hành vi khác giữa môi trường debug và non-debug.
        - Lưu ý: hành vi phụ thuộc phiên bản Windows/CPU/debugger; cần test thực tế, tránh dùng làm check duy nhất.
        - Code mẫu (x86/MSVC):
            ```
                bool CheckInt2D() {
                    bool debugged = true;
                    __try {
                        __asm {
                            xor eax, eax
                            int 0x2d
                            nop
                        }
                        debugged = false;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        debugged = true;
                    }
                    return debugged;
                }
            ```

    - DebugBreak()
        - Nguyên lý: gọi API chuẩn tạo breakpoint exception.
        - Ưu điểm: dễ viết, không cần inline asm.
        - Nhược điểm: dễ bị hook hoặc debugger cấu hình bỏ qua.
        - Code mẫu:
            ```
                bool CheckDebugBreak() {
                    __try {
                        DebugBreak();
                        return true;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        return false;
                    }
                }
            ```

    - ICE instruction (`0xF1` / `ICEBP`)
        - Nguyên lý: sinh `EXCEPTION_SINGLE_STEP`; một số debugger xử lý khác so với chạy thường.
        - Lưu ý: độ ổn định thấp giữa debugger khác nhau; có thể gây false positive.
        - Code mẫu (x86):
            ```
                bool CheckICE() {
                    bool debugged = false;
                    __try {
                        __asm _emit 0xF1
                        debugged = true;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        debugged = false;
                    }
                    return debugged;
                }
            ```

    - Stack Segment trick (`push ss; pop ss; pushf`)
        - Nguyên lý: lợi dụng khác biệt xử lý Trap Flag/interrupt window khi single-step.
        - Lưu ý: kỹ thuật cũ, phụ thuộc mạnh vào CPU/debugger; chủ yếu dùng nghiên cứu.
        - Pseudocode:
            ```
                ; push ss
                ; pop ss
                ; pushf
                ; đọc EFLAGS rồi kiểm tra TF có bị thay đổi bất thường không
            ```

    - POPF + Trap Flag
        - Nguyên lý: set TF trong EFLAGS để ép single-step exception ở instruction tiếp theo; quan sát luồng xử lý.
        - Dùng kết hợp với SEH/VEH để phân biệt debugger có can thiệp hay không.
        - Pseudocode:
            ```
                ; pushfd
                ; or dword ptr [esp], 0x100   ; set TF
                ; popfd
                ; nop                          ; instruction kế tiếp gây single-step
            ```

    - Instruction Prefixes
        - Nguyên lý: chèn prefix bất thường (`F3`, `64`, `65`, nhiều prefix liên tiếp) để tạo case khó decode/step.
        - Mục tiêu: gây lệch giữa CPU thật và debugger/disassembler khi theo dõi từng bước.
        - Lưu ý: dễ làm hỏng tính tương thích, chỉ nên dùng cục bộ cho bài CTF/research.

    - Khuyến nghị triển khai mục 6:
        - Không dùng 1 kỹ thuật duy nhất; nên combine 2-3 check rồi chấm điểm (score-based).
        - Tách check theo kiến trúc: x86 có inline asm thuận tiện hơn x64.
        - Luôn có fallback path để tránh crash trên máy người dùng hợp lệ.

7. Direct debugger interaction
    - Nhóm này tương tác trực tiếp với cơ chế debug event/NT API để làm giảm khả năng quan sát của debugger.

    - GenerateConsoleCtrlEvent + VEH/SEH
        - Nguyên lý: phát `CTRL_C_EVENT`; nếu debugger attach console process, có thể xuất hiện `DBG_CONTROL_C` theo luồng debug event.
        - Cách làm:
            - Đăng ký `SetConsoleCtrlHandler` hoặc VEH/SEH.
            - Gọi `GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)`.
            - Đo xem handler nào nhận trước và trạng thái exception.
        - Code khung:
            ```
                volatile LONG gSeen = 0;

                BOOL WINAPI CtrlHandler(DWORD ctrlType) {
                    if (ctrlType == CTRL_C_EVENT) {
                        InterlockedExchange(&gSeen, 1);
                        return TRUE;
                    }
                    return FALSE;
                }

                bool CheckCtrlCInteraction() {
                    gSeen = 0;
                    SetConsoleCtrlHandler(CtrlHandler, TRUE);
                    GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
                    Sleep(50);
                    SetConsoleCtrlHandler(CtrlHandler, FALSE);
                    return (gSeen == 0); // có thể nghi ngờ debugger can thiệp
                }
            ```

    - NtSetInformationThread(ThreadHideFromDebugger = 0x11)
        - Nguyên lý: yêu cầu kernel ẩn thread khỏi debugger; debugger thường không nhận event từ thread này.
        - Dùng khi nào: chạy anti-debug checks nền hoặc code nhạy cảm trong worker thread.
        - Rủi ro:
            - Có thể gây hành vi khó debug cho chính bạn.
            - Một số môi trường bảo mật/EDR hook API này.
        - Code mẫu đầy đủ hơn:
            ```
                typedef LONG NTSTATUS;
                typedef NTSTATUS (NTAPI* pNtSetInformationThread)(
                    HANDLE ThreadHandle,
                    ULONG ThreadInformationClass,
                    PVOID ThreadInformation,
                    ULONG ThreadInformationLength
                );

                bool HideCurrentThreadFromDebugger() {
                    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                    if (!ntdll) return false;

                    pNtSetInformationThread NtSetInformationThreadFn =
                        (pNtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");
                    if (!NtSetInformationThreadFn) return false;

                    const ULONG ThreadHideFromDebugger = 0x11;
                    NTSTATUS st = NtSetInformationThreadFn((HANDLE)-2, ThreadHideFromDebugger, NULL, 0);
                    return (st >= 0);
                }
            ```

    - DebugActiveProcessStop / Detach self-check
        - Ý tưởng: một số mẫu code kiểm tra trạng thái attach/detach không mong đợi để suy luận có debugger ngoài hay không.
        - Lưu ý: kỹ thuật này dễ gây tác dụng phụ, không phù hợp cho chương trình thông thường.

    - OutputDebugString side-channel
        - Ý tưởng: gọi `OutputDebugStringA/W` và đo/quan sát phản ứng môi trường debug.

        - Giá trị thực tế: thấp nếu đứng một mình, nhưng hữu ích khi cộng điểm cùng check khác.

