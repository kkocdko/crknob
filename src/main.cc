#include "MinHook.h"
#include <psapi.h>
#include <string.h>
#include <windows.h>

BOOL WINAPI FakeGetComputerName(LPWSTR, LPDWORD) { return 0; }

BOOL WINAPI FakeGetVolumeInfo(LPCWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD,
                              LPWSTR, DWORD) {
  return 0;
}

BOOL WINAPI FakeCrypt(DATA_BLOB *i, LPCWSTR, DATA_BLOB *, PVOID,
                      CRYPTPROTECT_PROMPTSTRUCT *, DWORD, DATA_BLOB *o) {
  o->cbData = i->cbData;
  o->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, o->cbData);
  memcpy(o->pbData, i->pbData, o->cbData);
  return TRUE;
}

typedef int (*EntryFn)();
EntryFn OriginEntry;

int Entry() {
  LPCWSTR loadedFlag = L"CRKNOB_LOADED";
  if (GetEnvironmentVariableW(loadedFlag, NULL, 0)) {
    // Hook some API about encryption and protect
    // `rlz/win/lib/machine_id_win.cc`, `components/os_crypt/os_crypt_win.cc`
    HMODULE kernel32 = LoadLibraryW(L"kernel32.dll");
    HMODULE crypt32 = LoadLibraryW(L"crypt32.dll");
    MH_CreateHook((LPVOID)GetProcAddress(kernel32, "GetComputerNameW"),
                  (LPVOID)FakeGetComputerName, NULL);
    MH_CreateHook((LPVOID)GetProcAddress(kernel32, "GetVolumeInformationW"),
                  (LPVOID)FakeGetVolumeInfo, NULL);
    MH_CreateHook((LPVOID)GetProcAddress(crypt32, "CryptProtectData"),
                  (LPVOID)FakeCrypt, NULL);
    MH_CreateHook((LPVOID)GetProcAddress(crypt32, "CryptUnprotectData"),
                  (LPVOID)FakeCrypt, NULL);
    MH_EnableHook(MH_ALL_HOOKS);
    return OriginEntry();
  }
  SetEnvironmentVariableW(loadedFlag, L"");

  LPCWSTR line = GetCommandLineW(); // Example: `"C:\foo.exe" --bar`
  LPCWSTR skipFirst = wcschr(line + 1, line[0] == L'"' ? L'"' : L' ') + 1;
  LPCWSTR insert = // Insert after argv[0], allow to overwrite again
      " --disable-features=RendererCodeIntegrity"
      " --force-local-ntp"
      " --user-data-dir=\"User Data\"" // TODO: absolute
      L" ";
  WCHAR args[32768]; // Max length, https://stackoverflow.com/a/28452546
  wcsncpy(args, line, (size_t)(skipFirst - line)); // Keep argv[0]
  wcscat(args, insert);
  wcscat(args, skipFirst);

  PROCESS_INFORMATION procInfo;
  STARTUPINFOW startInfo;
  startInfo.cb = sizeof(startInfo);
  CreateProcessW(NULL, args, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, 0,
                 &startInfo, &procInfo);
  ExitProcess(0);
}

__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID) {
  if (fdwReason != DLL_PROCESS_ATTACH)
    return TRUE;
  MODULEINFO info;
  GetModuleInformation(GetCurrentProcess(), GetModuleHandleW(NULL), &info,
                       sizeof(info));
  MH_Initialize();
  MH_CreateHook(info.EntryPoint, (LPVOID)Entry, (LPVOID *)&OriginEntry);
  MH_EnableHook(MH_ALL_HOOKS);
  return TRUE;
}
