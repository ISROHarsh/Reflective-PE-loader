#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <string.h>
#pragma pack(1)

typedef struct _PE_INFO_ {
  BOOL Brloc;
  BOOL Cleanup;
  DWORD Cleanup_RVA;
  LPVOID( * Get_Proc)(LPVOID, LPSTR);
  LPVOID( * Load_Dll)(LPSTR);
  LPVOID base;
}
PE_INFO, * LPE_INFO;

LPVOID Memory_Map_File(const char * Filename) {
  HANDLE f, mmap;

  if ((f = CreateFileA(Filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
    printf("[-] Failed To Open File");
    return NULL;
  }

  if ((mmap = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, 0, NULL)) == NULL) {
    printf("[-] CreateFileMappingA() Failed..");
    return NULL;
  }

  return MapViewOfFile(mmap, FILE_MAP_READ, 0, 0, 0);
}

BOOL Find_Process(const char * Process_Name, PHANDLE p) {
  PROCESSENTRY32 ps;
  HANDLE Snap;
  ps.dwSize = sizeof(ps);
  * p = NULL;
  if ((Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) {
    printf("[-] Failed To Enumurate Process");
    return FALSE;
  }

  if (!Process32First(Snap, & ps))
    return FALSE;

  do {
    if (!strcmp(Process_Name, ps.szExeFile)) {
      CloseHandle(Snap);
      * p = OpenProcess(PROCESS_ALL_ACCESS, 0, ps.th32ProcessID);
      if ( * p == NULL)
        return FALSE;
      else
        return TRUE;
    }
  } while (Process32Next(Snap, & ps));

  return FALSE;
}

BOOL Get_Rva(LPVOID base, PIMAGE_NT_HEADERS nt, char * name, PDWORD rva) {
  PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY) ImageRvaToVa(nt, base, nt -> OptionalHeader.DataDirectory[0].VirtualAddress, NULL);
  PDWORD Name;
  PDWORD addr;
  PWORD ord;
  int i;

  ord = (PWORD) ImageRvaToVa(nt, base, exp -> AddressOfNameOrdinals, NULL);
  Name = (PDWORD) ImageRvaToVa(nt, base, exp -> AddressOfNames, NULL);
  addr = (PDWORD) ImageRvaToVa(nt, base, exp -> AddressOfFunctions, NULL);

  for (i = 0; i < exp -> NumberOfNames; i++) {
    LPSTR Func = (LPSTR) ImageRvaToVa(nt, base, Name[i], NULL);
    if (!strcmp(Func, name)) {
      * rva = addr[ord[i]];
      return 1;
    }
  }

  return 0;
}

void Adjust_PE(LPE_INFO pe) {
  LPVOID base;
  PIMAGE_DOS_HEADER dos;
  PIMAGE_NT_HEADERS nt;
  PIMAGE_BASE_RELOCATION rloc;
  PIMAGE_TLS_DIRECTORY tls;
  PIMAGE_TLS_CALLBACK * Callback;
  PIMAGE_IMPORT_DESCRIPTOR imp;
  PIMAGE_THUNK_DATA Othunk, Fthunk;
  void( * Entry)(LPVOID, DWORD, LPVOID);

  base = pe -> base;
  dos = (PIMAGE_DOS_HEADER) base;
  nt = (PIMAGE_NT_HEADERS)(base + dos -> e_lfanew);

  if (!pe -> Brloc)
    goto Load_Import;

  Base_Reloc:
    if (!nt -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
      goto Load_Import;

  ULONG64 delta = (ULONG64) base - nt -> OptionalHeader.ImageBase;
  rloc = (PIMAGE_BASE_RELOCATION)(base + nt -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
  while (rloc -> VirtualAddress) {
    LPVOID Dest = base + rloc -> VirtualAddress;
    int n = (rloc -> SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
    int i;
    PWORD data = (PWORD)((LPVOID) rloc + sizeof(IMAGE_BASE_RELOCATION));
    for (i = 0; i < n; i++, data++) {
      if ((( * data) >> 12) == 10) {
        PULONG64 p = (PULONG64)(Dest + (( * data) & 0xfff));
        * p += delta;
      }
    }
    rloc = (PIMAGE_BASE_RELOCATION)((LPVOID) rloc + rloc -> SizeOfBlock);
  }

  Load_Import:
    if (!nt -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
      goto TLS;

  imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + nt -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  while (imp -> Name) {
    LPVOID dll = pe -> Load_Dll(base + imp -> Name);
    Othunk = (PIMAGE_THUNK_DATA)(base + imp -> OriginalFirstThunk);
    Fthunk = (PIMAGE_THUNK_DATA)(base + imp -> FirstThunk);

    if (!imp -> OriginalFirstThunk)
      Othunk = Fthunk;

    while (Othunk -> u1.AddressOfData) {
      if (Othunk -> u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        *(PULONG64) Fthunk = (ULONG64) pe -> Get_Proc(dll, (LPSTR) IMAGE_ORDINAL(Othunk -> u1.Ordinal));
      } else {
        PIMAGE_IMPORT_BY_NAME fn = (PIMAGE_IMPORT_BY_NAME)(base + Othunk -> u1.AddressOfData);
        *(PULONG64) Fthunk = (ULONG64) pe -> Get_Proc(dll, fn -> Name);
      }
      Othunk++;
      Fthunk++;
    }
    imp++;
  }
  TLS:
    if (!nt -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
      goto Execute_Entry;

  tls = (PIMAGE_TLS_DIRECTORY)(base + nt -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
  if (!tls -> AddressOfCallBacks)
    goto Execute_Entry;

  Callback = (PIMAGE_TLS_CALLBACK * ) tls -> AddressOfCallBacks;
  while ( * Callback) {
    ( * Callback)(base, 1, NULL);
    Callback++;
  }

  Execute_Entry:
    if (pe -> Cleanup) {
      Entry = (base + pe -> Cleanup_RVA);
      ( * Entry)(base, nt -> OptionalHeader.AddressOfEntryPoint, pe);
    }
  else {
    Entry = (base + nt -> OptionalHeader.AddressOfEntryPoint);
    ( * Entry)(base, 1, NULL);
  }

}

int main(int i, char * arg[]) {
  LPVOID base, Rbase;
  PIMAGE_DOS_HEADER dos;
  PIMAGE_NT_HEADERS nt;
  PIMAGE_SECTION_HEADER sec;
  HANDLE proc;
  PE_INFO pe;

  if (i != 3) {
    printf("[!] Usage %s <DLL> <Process Name>", arg[0]);
    return 1;
  }

  if ((base = Memory_Map_File(arg[1])) == NULL) {
    printf("[-] Failed To Memory Map File");
    return 1;
  }

  printf("[+] File is Memory Mapped Successfully\n");

  ZeroMemory( & pe, sizeof(pe));

  dos = (PIMAGE_DOS_HEADER) base;

  if (dos -> e_magic != 23117) {
    printf("\n[-] Invalid PE");
    return 1;
  }

  nt = (PIMAGE_NT_HEADERS)(base + dos -> e_lfanew);

  if (nt -> OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    printf("[-] Please use x64 PE");
    return 1;
  }

  if (!Find_Process(arg[2], & proc)) {
    printf("\n[-] Failed To Open Process");
    return 1;
  } else
    printf("[+] \'%s\' is Openned\n", arg[2]);

  printf("[!] Allocating Memory Into \'%s\'\n", arg[2]);

  if ((Rbase = VirtualAllocEx(proc, (LPVOID) nt -> OptionalHeader.ImageBase, nt -> OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
    pe.Brloc = TRUE;
    if ((Rbase = VirtualAllocEx(proc, NULL, nt -> OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
      printf("\n[-] Failed To Allocate Memory Into Remote Process");
      CloseHandle(proc);
      return 1;
    }
  }

  printf("\n[+] Copying File Content into Remote Process\n");

  WriteProcessMemory(proc, Rbase, base, nt -> OptionalHeader.SizeOfHeaders, NULL);

  sec = (PIMAGE_SECTION_HEADER)((LPVOID) nt + sizeof(IMAGE_NT_HEADERS));

  for (i = 0; i < nt -> FileHeader.NumberOfSections; i++) {
    WriteProcessMemory(proc, Rbase + sec -> VirtualAddress, base + sec -> PointerToRawData, sec -> SizeOfRawData, NULL);
    sec++;
  }

  pe.base = Rbase;
  pe.Get_Proc = GetProcAddress;
  pe.Load_Dll = LoadLibraryA;

  if (Get_Rva(base, nt, "_PE_CLEANUP", & pe.Cleanup_RVA)) {
    pe.Cleanup = TRUE;
  }

  DWORD len = (DWORD)((ULONG64) main - (ULONG64) Adjust_PE);
  LPVOID temp = VirtualAllocEx(proc, NULL, len + sizeof(pe), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (temp == NULL) {
    printf("\n[-] Insufficiant Memory For PE Configurator\n");
    VirtualFreeEx(proc, Rbase, 0, MEM_RELEASE);
    return 1;
  }

  WriteProcessMemory(proc, temp, & pe, sizeof(pe), NULL);
  WriteProcessMemory(proc, temp + sizeof(pe), Adjust_PE, len, NULL);

  printf("\n[+] Configuring PE and Executing...");
  if (!CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE) temp + sizeof(pe), temp, 0, NULL)) {
    printf("\n[-] Failed To Create Thread..");
    VirtualFreeEx(proc, Rbase, 0, MEM_RELEASE);
    return 1;
  }
  CloseHandle(proc);
  return 0;
}