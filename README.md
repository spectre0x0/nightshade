# nightshade

A minimal Windows PE export resolver. Parses the export table of a
loaded module without calling `GetProcAddress`, resolves function
addresses by hash instead of by name, and stores API identifiers as
path-shaped hex strings.

## Overview

Hash-based API resolution is a standard technique for reducing static
visibility of a binary's dependencies. Import scanners look at the IAT
and at plaintext strings. If the resolver never calls `GetProcAddress`
and never stores the plaintext name, neither check finds anything.

nightshade implements that resolver from scratch: manual PE header
traversal, djb2 hashing, and a precomputed phonebook that maps an
encoded path and a hash to a resolved function pointer. The demo
resolves `MessageBoxA` out of `user32.dll` and calls it through the
pointer.

## Design

`GetFuncAddrByHash` walks the mapped image the same way the Windows
loader does:

- DOS header at the module base, validated against `IMAGE_DOS_SIGNATURE`
- NT headers at `base + e_lfanew`, validated against `IMAGE_NT_SIGNATURE`
- Export directory RVA from `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]`
- Three parallel arrays: `AddressOfNames`, `AddressOfNameOrdinals`,
  `AddressOfFunctions`

The loop hashes each exported name and compares against the target. On
a match it returns `base + functions[ordinals[i]]`. No import table
lookup, no `GetProcAddress`, no loader assistance.

`HashDjb2` is a 32-bit non-cryptographic string hash. It is used here
because it is fast, deterministic, and stable across compiler versions
when the input is cast to `unsigned char`. The names being hashed are
public API names, not secrets, so cryptographic strength is not
relevant. What matters is collision resistance across a few thousand
export names, which djb2 comfortably provides.

The phonebook stores each entry as an encoded path and a hash:

    { "C:\\Windows\\System32\\drivers\\etc\\4D657373616765426F7841",
      0x384F14B4, NULL }

The path prefix is camouflage. The hex payload decodes back to the
original API name. Both constants were precomputed offline and
verified against `GetProcAddress` before being frozen into the source.
The encoder that produced them is not part of the build; the constants
are static data.

## Build

    gcc -Wall -Wextra -O2 -s -o nightshade.exe nightshade.c

MinGW-w64 GCC 11.1.0, Windows 10/11 x64. The `-s` flag strips symbols
at link time.

## Verification

Import table:

    > objdump -p .\nightshade.exe | Select-String "MessageBoxA"
    (no output)

    > objdump -p .\nightshade.exe | Select-String "DLL Name"

            DLL Name: KERNEL32.dll
            DLL Name: msvcrt.dll

`user32.dll` is not present. `MessageBoxA` is not present. A static
import scanner sees no dependency on the popup API.

Strings:

    > strings .\nightshade.exe | Select-String "MessageBox"
    (no output)

The plaintext name does not appear in the binary. The resolver
operates only on `0x384F14B4`; the encoded path is stored separately
as reference data.

Symbols:

    > objdump -t .\nightshade.exe
    no symbols

Stripped at link time.

Disassembly:

There is no `call MessageBoxA` instruction. The call is indirect
through the function pointer stored in `g_book[0].resolved`. Static
search for the call site returns nothing; the analyst has to read the
resolver and trace the data flow from the phonebook entry to the
indirect call.

## Scope and limitations

`user32.dll` remains in the string table because the demo calls
`LoadLibraryA` to load the module. Resolving module bases through the
PEB and resolving `LoadLibraryA` itself by hash would remove this
string. That is the next iteration, not part of this build.

`LoadLibraryA` and `GetProcAddress` remain in the import table because
MinGW's C runtime startup code imports them. Removing them requires
building without the default start files and providing a custom entry
point. Again, a larger change than this resolver needed.

The path-shaped strings carry hex payloads and will look unusual to a
scanner that flags high entropy or fake filesystem paths. A hash-only
phonebook (no encoded path in the struct) is less conspicuous. Both
approaches are valid; this build shows the path-based variant because
the encoding step is the more interesting part.

Forwarded exports are not followed. If a target name resolves to a
forwarder string (something like `NTDLL.RtlFoo`), the resolver returns
a pointer to the string rather than following the chain. This is
fine for `kernel32` and `user32` primitives but breaks on `ntdll`.

x86 is not supported. The resolver is written against `IMAGE_NT_HEADERS`
in its 64-bit form.

## Notes on the technique

Hash-based resolution is not novel. It appears in published loaders,
in reflective DLL injection implementations, and in most modern
shellcode stagers. What changes between implementations is the hash
function, the way the phonebook is stored, and whether the resolver
walks the PEB or relies on `LoadLibrary`.

The value of this build is in the resolver, not the obfuscation layer.
Reading the export table directly, hashing names in the loop, and
calling through a function pointer are the three mechanical steps that
make hash-based resolution work. Everything else is presentation.

## Authorized use

Research, lab work, and authorized engagements only. The binary does
not inject, does not touch other processes, and does nothing beyond
resolving one function and calling it. Do not run it against systems
you do not own or do not have written authorization to test.

## License

MIT