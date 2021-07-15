#include "MinHook.h"
#include <cwchar>
#include <psapi.h>
#include <windows.h>

// #include <string>
// void Msg(std::string msg) { MessageBox(NULL, msg.c_str(), "Msg", MB_OK); }

BOOL WINAPI FakeCryptProtectData(DATA_BLOB *pIn, LPCWSTR _0, DATA_BLOB *_1,
                                 PVOID _2, CRYPTPROTECT_PROMPTSTRUCT *_3,
                                 DWORD _4, DATA_BLOB *pOut) {
  pOut->cbData = pIn->cbData;
  pOut->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, pOut->cbData);
  memcpy(pOut->pbData, pIn->pbData, pOut->cbData);
  return true;
}

BOOL WINAPI FakeCryptUnprotectData(DATA_BLOB *pIn, LPWSTR *_0, DATA_BLOB *_1,
                                   PVOID _2, CRYPTPROTECT_PROMPTSTRUCT *_3,
                                   DWORD _4, DATA_BLOB *pOut) {
  pOut->cbData = pIn->cbData;
  pOut->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, pOut->cbData);
  memcpy(pOut->pbData, pIn->pbData, pOut->cbData);
  return true;
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
                (LPVOID)FakeCryptProtectData, NULL);
  MH_CreateHook((LPVOID)GetProcAddress(crypt32, "CryptUnprotectData"),
                (LPVOID)FakeCryptUnprotectData, NULL);
  MH_EnableHook(MH_ALL_HOOKS);
}

DWORD GetParentPID() {
  typedef struct {
    size_t ExitStatus;
    size_t PebBaseAddress;
    size_t AffinityMask;
    size_t BasePriority;
    size_t UniqueProcessId;
    size_t InheritedFromUniqueProcessId;
  } PROCESS_BASIC_INFORMATION;
  typedef NTSTATUS(WINAPI * FnNtQueryInformationProcess)(HANDLE, UINT, PVOID,
                                                         ULONG, PULONG);
  auto NtQueryInformationProcess = (FnNtQueryInformationProcess)GetProcAddress(
      GetModuleHandle("ntdll"), "NtQueryInformationProcess");
  PROCESS_BASIC_INFORMATION info;
  NtQueryInformationProcess(GetCurrentProcess(), 0, &info, sizeof(info), NULL);
  return (DWORD)info.InheritedFromUniqueProcessId;
}

void GetParentPath(char *path) {
  HANDLE hProcess =
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetParentPID());
  DWORD dwSize = MAX_PATH;
  QueryFullProcessImageName(hProcess, 0, path, &dwSize);
  CloseHandle(hProcess);
}

typedef int (*EntryFn)();
EntryFn OriginEntry = NULL;

int Entry() {
  LoadHooks();

  char exePath[MAX_PATH];
  char parentPath[MAX_PATH];
  GetModuleFileName(NULL, exePath, MAX_PATH);
  GetParentPath(parentPath);

  // Parent process is chromium
  if (strcmp(parentPath, exePath) == 0)
    return OriginEntry();

  char *cmdLine = GetCommandLine(); // `"C:\foo.exe"   --bar`
  char *skipFirst = strchr(cmdLine + 1, cmdLine[0] == '"' ? '"' : ' ') + 1;
  while (skipFirst[0] == ' ')
    skipFirst += 1;

  const char *loadedMark = "--with-crknob ";
  if (strncmp(skipFirst, loadedMark, strlen(loadedMark)) == 0)
    return OriginEntry(); // Already loaded, return to origin entry

  const char *insert = // Insert after argv[0], allow to overwrite from cmd
      " --with-crknob"
      // " --user-data-dir=\"User Data Test\""
      " --user-data-dir=\"User Data\"" // TODO: absolute
      " --force-local-ntp"
      " --disable-features=RendererCodeIntegrity"
      " ";

  size_t firstLen = skipFirst - cmdLine; // Length of argv[0]
  size_t len = firstLen + strlen(insert) + strlen(skipFirst) + 4 /* \0 */;
  char *args = (char *)calloc(len, sizeof(char));
  strncpy(args, cmdLine, firstLen);
  strcat(args, insert);
  strcat(args, skipFirst);

  STARTUPINFO startInfo;
  PROCESS_INFORMATION procInfo;
  startInfo.cb = sizeof(STARTUPINFO);
  CreateProcess(exePath, args, NULL, NULL, false, NORMAL_PRIORITY_CLASS, NULL,
                0, &startInfo, &procInfo);

  free(args);
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
