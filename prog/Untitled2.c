#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

typedef unsigned char byte;

byte v1[4];
byte v11[26];
byte v16[26];
char input[100];
volatile LONG g_dbgPrintHandled = 0;

LONG WINAPI dbg_print_exception_handler(struct _EXCEPTION_POINTERS* exceptionInfo) {
    if (exceptionInfo != NULL &&
        exceptionInfo->ExceptionRecord != NULL &&
        exceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C) {
        g_dbgPrintHandled = 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void continue_execution(void) {
}

int sub_16381836() {
    BOOL remoteDebugger = FALSE;
    CONTEXT context;
    PVOID vectoredHandler;
    LARGE_INTEGER freq, t1, t2;
    double elapsedMs;

    if (IsDebuggerPresent() ||
        (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger)) {
        return 1;
    }

    g_dbgPrintHandled = 0;
    vectoredHandler = AddVectoredExceptionHandler(1, dbg_print_exception_handler);
    if (vectoredHandler != NULL) {
        RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, NULL);
        RemoveVectoredExceptionHandler(vectoredHandler);
        if (!g_dbgPrintHandled) {
            return 2;
        }
    }

    if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&t1)) {
        volatile int spin = 0;
        for (int i = 0; i < 40000000; i++) {
            spin += i;
        }
        (void)spin;
        if (QueryPerformanceCounter(&t2)) {
            elapsedMs = ((double)(t2.QuadPart - t1.QuadPart) * 1000.0) / (double)freq.QuadPart;
            if (elapsedMs > 1500.0) {
                return 3;
            }
        }
    }

    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    RtlCaptureContext(&context);
    if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0) {
        return 4;
    }

    return 0;

}

void sub_13373618() {
    int status = sub_16381836();

    if (status == 0) {
        continue_execution();
    }
    if (status == 1) {
        system("start \"\" \"https://www.youtube.com/watch?v=PD61lIYrG-M&list=RDPD61lIYrG-M\"");
        exit(1);
    }
    if (status == 2) {
        system("start \"\" \"https://www.youtube.com/watch?v=ebRLexTgylw&list=RDebRLexTgylw\"");
        exit(1);
    }
    if (status == 3) {
        system("start \"\" \"https://www.youtube.com/watch?v=BbeeuzU5Qc8\"");
        exit(1);
    }
    if (status == 4) {
        exit(1);
    }
}

int sub_004b5341(byte* key, byte* S) {
    int i, j = 0;
    for (i = 0; i < 256; i++) {
        S[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % 4]) % 256;
        byte temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    return 0;
}

int sub_50524741(byte* S, byte* input_data, byte* output, int length) {
    int i = 0, j = 0;
    for (int k = 0; k < length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        byte temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        byte keystream = S[(S[i] + S[j]) % 256];
        output[k] = input_data[k] ^ keystream;  // XOR với keystream để mã hóa
    }
    return 0;
}

int sub_00656e63(byte* key, char* input, byte* output, int input_length) {
    byte S[256];
    sub_004b5341(key, S);
    sub_50524741(S, (byte*)input, output, input_length);
    return 0;
}


int main() {
    memset(v11, 0, 26);

    v1[0] = 0x00;
    v1[1] = 0x2A;
    v1[2] = 0x8C;
    v1[3] = 0xFF;
    v16[0] = 0xbe;
    v16[1] = 0x12;
    v16[2] = 0x9f;
    v16[3] = 0x4a;
    v16[4] = 0xbd;
    v16[5] = 0xdb;
    v16[6] = 0x98;
    v16[7] = 0xe7;
    v16[8] = 0x3a;
    v16[9] = 0xda;
    v16[10] = 0x16;
    v16[11] = 0x90;
    v16[12] = 0x39;
    v16[13] = 0xb3;
    v16[14] = 0x2b;
    v16[15] = 0xfa;
    v16[16] = 0x40;
    v16[17] = 0x8c;
    v16[18] = 0x43;
    v16[19] = 0x2d;
    v16[20] = 0x1d;
    v16[21] = 0xc5;
    v16[22] = 0x56;
    v16[23] = 0xdb;
    v16[24] = 0xde;
    v16[25] = 0xed;

    sub_13373618();
    printf("Enter the flag: ");
    fgets(input, sizeof(input), stdin);
    // Remove newline character if present
    input[strcspn(input, "\n")] = '\0';
    byte output[100];
    sub_00656e63(v1, input, output, strlen(input));
    if (memcmp(output, v16, 26) == 0) {
        printf("Correct flag!\n");
    }
    else {
        printf("Incorrect flag.\n");
    }
    return 0;
}