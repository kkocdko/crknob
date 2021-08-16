#include "MinHook.h"
#include <psapi.h>
#include <string.h>
#include <windows.h>

BOOL WINAPI FakeCryptData(DATA_BLOB *pIn, LPWSTR *_0, DATA_BLOB *_1, PVOID _2,
                          CRYPTPROTECT_PROMPTSTRUCT *_3, DWORD _4,
                          DATA_BLOB *pOut) {
  pOut->cbData = pIn->cbData;
  pOut->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, pOut->cbData);
  memcpy(pOut->pbData, pIn->pbData, pOut->cbData);
  return TRUE;
}

BOOL WINAPI FakeGetComputerName(LPTSTR _0, LPDWORD _1) { return 0; }

BOOL WINAPI FakeGetVolumeInformation(LPCTSTR _0, LPTSTR _1, DWORD _2,
                                     LPDWORD _3, LPDWORD _4, LPDWORD _5,
                                     LPTSTR _6, DWORD _7) {
  return 0;
}

void LoadHooks() {
  // Hook some API about encryption and protect
  // `rlz/win/lib/machine_id_win.cc` and `components/os_crypt/os_crypt_win.cc`
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
}

typedef int (*EntryFn)();
EntryFn OriginEntry = NULL;

int Entry() {
  LoadHooks();

  char *cmdLine = GetCommandLine(); // Example: ["C:\foo.exe"   --bar]
  char *skipFirst = strchr(cmdLine + 1, cmdLine[0] == '"' ? '"' : ' ') + 1;
  while (*skipFirst == ' ')
    skipFirst += 1;

  const char *loadedMark = "--with-crknob ";
  if (strncmp(skipFirst, loadedMark, strlen(loadedMark)) == 0)
    return OriginEntry(); // Already loaded, return to origin entry

  const char *insert = // Insert after argv[0], allow to overwrite from cmd
      " --with-crknob"
      " --force-local-ntp"
      " --disable-features=RendererCodeIntegrity"
      " --user-data-dir=\"User Data\"" // TODO: absolute
      " ";

  char args[32767]; // https://devblogs.microsoft.com/oldnewthing/2003/12/10
  strncpy(args, cmdLine, skipFirst - cmdLine); // argv[0]
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
