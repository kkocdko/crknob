#include "MinHook.h"
#include <cwchar>
#include <psapi.h>
#include <windows.h>

// void AssertMsg(bool condition, std::string msg) {
//   if (!condition) {
//     MessageBox(NULL, msg.c_str(), "AssertMsg", MB_OK);
//     ExitProcess(1);
//   }
// }

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

  // chromium/rlz/win/lib/machine_id_win.cc
  HMODULE kernel32 = LoadLibraryW(L"kernel32.dll");
  auto GetComputerNameW = (LPVOID)GetProcAddress(kernel32, "GetComputerNameW");
  auto GetVolumeInformationW =
      (LPVOID)GetProcAddress(kernel32, "GetVolumeInformationW");
  MH_CreateHook(GetComputerNameW, (LPVOID)FakeGetComputerName, NULL);
  MH_EnableHook(GetComputerNameW);
  MH_CreateHook(GetVolumeInformationW, (LPVOID)FakeGetVolumeInformation, NULL);
  MH_EnableHook(GetVolumeInformationW);

  // chromium/components/os_crypt/os_crypt_win.cc
  HMODULE crypt32 = LoadLibraryW(L"crypt32.dll");
  auto CryptProtectData = (LPVOID)GetProcAddress(crypt32, "CryptProtectData");
  auto CryptUnprotectData =
      (LPVOID)GetProcAddress(crypt32, "CryptUnprotectData");
  MH_CreateHook(CryptProtectData, (LPVOID)FakeCryptProtectData, NULL);
  MH_EnableHook(CryptProtectData);
  MH_CreateHook(CryptUnprotectData, (LPVOID)FakeCryptUnprotectData, NULL);
  MH_EnableHook(CryptUnprotectData);
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
  const NTSTATUS NTSTATUS_SUCCESS = 0x00000000L;
  auto NtQueryInformationProcess = (FnNtQueryInformationProcess)GetProcAddress(
      GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
  PROCESS_BASIC_INFORMATION info;
  NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0,
                                              (PVOID)&info, sizeof(info), NULL);
  return status == NTSTATUS_SUCCESS ? (DWORD)info.InheritedFromUniqueProcessId
                                    : 0;
}

void GetParentPath(wchar_t *path) {
  HANDLE hProcess =
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetParentPID());
  DWORD dwSize = MAX_PATH;
  QueryFullProcessImageNameW(hProcess, 0, path, &dwSize);
  CloseHandle(hProcess);
}

typedef int (*EntryFn)();
EntryFn OriginEntry = NULL;

int Entry() {
  LoadHooks();

  wchar_t exePath[MAX_PATH];
  wchar_t parentPath[MAX_PATH];
  GetModuleFileNameW(NULL, exePath, MAX_PATH);
  GetParentPath(parentPath);

  // Parent process is chromium
  if (wcscmp(parentPath, exePath) == 0)
    return OriginEntry();

  wchar_t *cmdLine = GetCommandLineW();
  wchar_t *skipFirst = cmdLine + wcslen(exePath);
  // 1. exePath = [C:\foo.exe]
  // 2. exePath = ["C:\foo.exe"]
  // 3. cmdLine = ["C:\foo.exe" --bar]
  // 4. cmdLine = ["C:\foo.exe"   --bar]

  while (skipFirst[0] != ' ') // Adapt to 1st & 3rd
    skipFirst += 1;

  auto firstLen = skipFirst - cmdLine; // Length of argv[0]

  while (skipFirst[0] == ' ') // Adapt to the 4th case
    skipFirst += 1;

  const wchar_t *loadedMark = L"--with-crknob ";
  if (wcsncmp(skipFirst, loadedMark, wcslen(loadedMark)) == 0)
    return OriginEntry(); // Already loaded, return to origin entry

  const wchar_t *insert = // Insert after argv[0], allow to overwrite from cmd
      L" --with-crknob"
      // L" --user-data-dir=\"User Data Test\""
      L" --user-data-dir=\"User Data\"" // TODO: absolute
      L" --force-local-ntp"
      L" --disable-features=RendererCodeIntegrity,ReadLater";

  size_t size = firstLen + wcslen(insert) + wcslen(skipFirst) + 4 /* \0 */;
  wchar_t *args = (wchar_t *)calloc(size, sizeof(wchar_t));
  wcsncpy(args, cmdLine, firstLen);
  wcscat(args, insert);
  wcscat(args, skipFirst);

  STARTUPINFOW startInfo = {0};
  PROCESS_INFORMATION procInfo = {0};
  startInfo.cb = sizeof(STARTUPINFO);
  CreateProcessW(exePath, args, NULL, NULL, false, NULL, NULL, 0, &startInfo,
                 &procInfo);

  free(args);
  ExitProcess(0);
}

BOOL WINAPI DllMain(HINSTANCE _hinstDLL, DWORD fdwReason, LPVOID _lpReserved) {
  if (fdwReason != DLL_PROCESS_ATTACH)
    return TRUE;

  MODULEINFO info = {0};
  GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &info,
                       sizeof(MODULEINFO));
  LPVOID entry = info.EntryPoint;
  MH_Initialize();
  MH_CreateHook(entry, (LPVOID)Entry, (LPVOID *)&OriginEntry);
  MH_EnableHook(entry);
  return TRUE;
}
