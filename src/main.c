#include "MinHook.h"
#include <psapi.h>
#include <string.h>
#include <windows.h>

BOOL WINAPI FakeGetComputerName(LPWSTR _0, LPDWORD _1) { return 0; }

BOOL WINAPI FakeGetVolumeInfo(LPCWSTR _0, LPWSTR _1, DWORD _2, LPDWORD _3,
                              LPDWORD _4, LPDWORD _5, LPWSTR _6, DWORD _7) {
  return 0;
}

BOOL WINAPI FakeCrypt(DATA_BLOB *i, LPCWSTR _1, DATA_BLOB *_2, PVOID _3,
                      CRYPTPROTECT_PROMPTSTRUCT *_4, DWORD _5, DATA_BLOB *o) {
  o->cbData = i->cbData;
  o->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, o->cbData);
  memcpy(o->pbData, i->pbData, o->cbData);
  return TRUE;
}

FARPROC OriginEntry;

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
  LPCWSTR skipFirst = wcschr(line + 1, line[0] == '"' ? '"' : ' ') + 1;
  LPCWSTR insert = // Insert after argv[0], allow to overwrite again
      " --disable-features=RendererCodeIntegrity"
      " --force-local-ntp"
      " --user-data-dir=\"User Data\"" // TODO: absolute
      L" ";
  WCHAR args[32768]; // Max length, https://stackoverflow.com/a/28452546
  wcsncpy(args, line, skipFirst - line); // Keep argv[0]
  wcscat(args, insert);
  wcscat(args, skipFirst);

  PROCESS_INFORMATION procInfo;
  STARTUPINFOW startInfo;
  startInfo.cb = sizeof(startInfo);
  CreateProcessW(NULL, args, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, 0,
                 &startInfo, &procInfo);
  ExitProcess(0);
}

__declspec(dllexport) BOOL WINAPI
    DllMain(HINSTANCE _hinstDLL, DWORD fdwReason, LPVOID _lpReserved) {
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
