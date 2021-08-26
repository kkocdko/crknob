#include "MinHook.h"
#include <psapi.h>
#include <string.h>
#include <windows.h>

BOOL WINAPI FakeGetComputerName(LPTSTR _0, LPDWORD _1) { return 0; }

BOOL WINAPI FakeGetVolumeInformation(LPCTSTR _0, LPTSTR _1, DWORD _2,
                                     LPDWORD _3, LPDWORD _4, LPDWORD _5,
                                     LPTSTR _6, DWORD _7) {
  return 0;
}

BOOL WINAPI FakeCryptData(DATA_BLOB *pIn, LPWSTR *_0, DATA_BLOB *_1, PVOID _2,
                          CRYPTPROTECT_PROMPTSTRUCT *_3, DWORD _4,
                          DATA_BLOB *pOut) {
  pOut->cbData = pIn->cbData;
  pOut->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, pOut->cbData);
  memcpy(pOut->pbData, pIn->pbData, pOut->cbData);
  return TRUE;
}

typedef int (*EntryFn)();
EntryFn OriginEntry = NULL;

int Entry() {
  // Hook some API about encryption and protect
  // `rlz/win/lib/machine_id_win.cc`, `components/os_crypt/os_crypt_win.cc`
  HMODULE kernel32 = LoadLibrary("kernel32.dll");
  HMODULE crypt32 = LoadLibrary("crypt32.dll");
  MH_CreateHook((LPVOID)GetProcAddress(kernel32, "GetComputerNameW"),
                (LPVOID)FakeGetComputerName, NULL);
  MH_CreateHook((LPVOID)GetProcAddress(kernel32, "GetVolumeInformationW"),
                (LPVOID)FakeGetVolumeInformation, NULL);
  MH_CreateHook((LPVOID)GetProcAddress(crypt32, "CryptProtectData"),
                (LPVOID)FakeCryptData, NULL);
  MH_CreateHook((LPVOID)GetProcAddress(crypt32, "CryptUnprotectData"),
                (LPVOID)FakeCryptData, NULL);
  MH_EnableHook(MH_ALL_HOOKS);

  const char *loadedFlag = "CRKNOB_LOADED";
  if (GetEnvironmentVariable(loadedFlag, NULL, 0))
    return OriginEntry();
  SetEnvironmentVariable(loadedFlag, "");

  const char *line = GetCommandLine(); // Example: `"C:\foo.exe" --bar`
  const char *skipFirst = strchr(line + 1, line[0] == '"' ? '"' : ' ') + 1;
  const char *insert = // Insert after argv[0], allow to overwrite again
      " --disable-features=RendererCodeIntegrity"
      " --force-local-ntp"
      " --user-data-dir=\"User Data\"" // TODO: absolute
      " ";
  char args[32768] = {0}; // Max length, https://stackoverflow.com/a/28452546
  strncpy(args, line, skipFirst - line); // Keep argv[0]
  strcat(args, insert);
  strcat(args, skipFirst);

  PROCESS_INFORMATION procInfo;
  STARTUPINFO startInfo;
  startInfo.cb = sizeof(STARTUPINFO);
  CreateProcess(NULL, args, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, 0,
                &startInfo, &procInfo);
  ExitProcess(0);
}

__declspec(dllexport) BOOL WINAPI
    DllMain(HINSTANCE _hinstDLL, DWORD fdwReason, LPVOID _lpReserved) {
  if (fdwReason != DLL_PROCESS_ATTACH)
    return TRUE;
  MODULEINFO info;
  GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &info,
                       sizeof(MODULEINFO));
  MH_Initialize();
  MH_CreateHook(info.EntryPoint, (LPVOID)Entry, (LPVOID *)&OriginEntry);
  MH_EnableHook(MH_ALL_HOOKS);
  return TRUE;
}
