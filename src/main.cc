#include "MinHook.h"
#include <psapi.h>
#include <string>
#include <windows.h>

#ifdef _WIN64
typedef uint64_t MWORD;
#else
typedef uint32_t MWORD;
#endif

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
    MWORD ExitStatus;
    MWORD PebBaseAddress;
    MWORD AffinityMask;
    MWORD BasePriority;
    MWORD UniqueProcessId;
    MWORD InheritedFromUniqueProcessId;
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

void PushArg(std::wstring &base, std::wstring item) {
  // Add quotes if needed
  bool quotes = (item[0] != '"') &&                     // No quote at begin
                (*--item.end() != '"') &&               // No quote at end
                (item.find(' ') != std::wstring::npos); // Has spaces
  base += quotes ? L'"' + item + L'"' : item;
  base += L' ';
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
  if (_wcsicmp(parentPath, exePath) == 0)
    return OriginEntry();

  int originArgsLen;
  LPWSTR *originArgs = CommandLineToArgvW(GetCommandLineW(), &originArgsLen);
  // Already loaded
  if (_wcsicmp(originArgs[1], L"--with-crknob") == 0)
    return OriginEntry();

  std::wstring args;
  PushArg(args, originArgs[0]);    // Keep argv[0]
  PushArg(args, L"--with-crknob"); // Loaded flag

  // Custom switches first, enable to override from terminal
  // PushArg(args, L"--user-data-dir=\"User Data Test\"");
  PushArg(args, L"--user-data-dir=\"User Data\""); // TODO: absolute
  PushArg(args, L"--force-local-ntp");
  PushArg(args, L"--enable-features=OverlayScrollbar");
  PushArg(args, L"--disable-features=RendererCodeIntegrity,ReadLater");

  // Keep original args, skip argv[0]
  for (int i = 1; i < originArgsLen; i++)
    PushArg(args, originArgs[i]);
  LocalFree(originArgs);

  STARTUPINFOW startInfo = {0};
  PROCESS_INFORMATION procInfo = {0};
  startInfo.cb = sizeof(STARTUPINFO);
  CreateProcessW(exePath, (LPWSTR)args.c_str(), NULL, NULL, false, NULL, NULL,
                 0, &startInfo, &procInfo);

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
