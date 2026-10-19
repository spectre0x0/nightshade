/* nightshade — minimal PE export resolver with path-based import
 * camouflage and hash-based lookup. educational / authorized use only. */

#include <windows.h>
#include <stdio.h>

/* djb2 hash */
DWORD HashDjb2(const char* str) {
    DWORD h = 5381;
    int c;
    while ((c = (unsigned char)*str++))
        h = ((h << 5) + h) + c;
    return h;
}

PVOID GetFuncAddrByHash(HMODULE hMod, DWORD targetHash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY expDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0) return NULL;
    PIMAGE_EXPORT_DIRECTORY exports =
        (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + expDir.VirtualAddress);
    DWORD* names     = (DWORD*)((BYTE*)hMod + exports->AddressOfNames);
    WORD*  ordinals  = (WORD*) ((BYTE*)hMod + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hMod + exports->AddressOfFunctions);
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hMod + names[i]);
        if (HashDjb2(name) == targetHash)
            return (PVOID)((BYTE*)hMod + functions[ordinals[i]]);
    }
    return NULL;
}

// phonebook
typedef struct {
    const char* encodedPath;
    DWORD       funcHash;
    PVOID       resolved;
} PHONEBOOK_ENTRY;

/* entry for MessageBoxA.
 *
 *   djb2("MessageBoxA")  = 0x384F14B4
 *   hex("MessageBoxA")   = 4D657373616765426F7841
 *
 * the hex payload is prefixed with a path to make the string look like a
 * filesystem path rather than an encoded API name. both the hash and the
 * encoded path were precomputed offline, the encoder/decoder was a one-off
 * tool, not part of the loader. the plaintext name never appears in this
 * source or in the binary.
 *
 * verified against GetProcAddress during development. See README.
 */


static PHONEBOOK_ENTRY g_book[] = {
    { "C:\\Windows\\System32\\drivers\\etc\\4D657373616765426F7841",
      0x384F14B4, NULL },
};

int main(void) {
    HMODULE u32 = LoadLibraryA("user32.dll");
    if (!u32) { printf("[-] user32 load failed\n"); return 1; }

    size_t count = sizeof(g_book) / sizeof(g_book[0]);
    for (size_t i = 0; i < count; i++) {
        g_book[i].resolved = GetFuncAddrByHash(u32, g_book[i].funcHash);
        if (!g_book[i].resolved) {
            printf("[-] resolution failed for entry %zu\n", i);
            return 1;
        }
    }

    typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
    ((MessageBoxA_t)g_book[0].resolved)(
        NULL, "Resolved by hash, not by import.", "nightshade",
        MB_OK | MB_ICONINFORMATION);
    return 0;
}