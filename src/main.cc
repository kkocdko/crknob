#include "MinHook.h"
#include <psapi.h>
#include <string>
#include <vector>
#include <windows.h>

#ifdef _WIN64
typedef uint64_t MWORD;
#else
typedef uint32_t MWORD;
#endif

inline void AssertMsg(bool condition, std::string msg) {
  if (!condition) {
    MessageBox(NULL, msg.c_str(), "AssertMsg", MB_OK);
    exit(1);
  }
}

BOOL WINAPI FakeCryptProtectData(_In_ DATA_BLOB *pIn, _In_opt_ LPCWSTR _0,
                                 _In_opt_ DATA_BLOB *_1, _Reserved_ PVOID _2,
                                 _In_opt_ CRYPTPROTECT_PROMPTSTRUCT *_3,
                                 _In_ DWORD _4, _Out_ DATA_BLOB *pOut) {
  pOut->cbData = pIn->cbData;
  pOut->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, pOut->cbData);
  memcpy(pOut->pbData, pIn->pbData, pOut->cbData);
  return true;
}

BOOL WINAPI FakeCryptUnprotectData(_In_ DATA_BLOB *pIn, _Out_opt_ LPWSTR *_0,
                                   _In_opt_ DATA_BLOB *_1, _Reserved_ PVOID _2,
                                   _In_opt_ CRYPTPROTECT_PROMPTSTRUCT *_3,
                                   _In_ DWORD _4, _Out_ DATA_BLOB *pOut) {
  pOut->cbData = pIn->cbData;
  pOut->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, pOut->cbData);
  memcpy(pOut->pbData, pIn->pbData, pOut->cbData);
  return true;
}

BOOL WINAPI FakeGetComputerName(_Out_ LPTSTR _0, _Inout_ LPDWORD _1) {
  return 0;
}

BOOL WINAPI FakeGetVolumeInformation(_In_opt_ LPCTSTR _0, _Out_opt_ LPTSTR _1,
                                     _In_ DWORD _2, _Out_opt_ LPDWORD _3,
                                     _Out_opt_ LPDWORD _4, _Out_opt_ LPDWORD _5,
                                     _Out_opt_ LPTSTR _6, _In_ DWORD _7) {
  return 0;
}

void MakePortable() {
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

DWORD GetParentProcessID() {
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
  if (NtQueryInformationProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0,
                                                (PVOID)&pbi, sizeof(pbi), NULL);
    if (!status) {
      return (DWORD)pbi.InheritedFromUniqueProcessId;
    }
  }
  return 0;
}

void GetParentPath(wchar_t *path) {
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                GetParentProcessID());
  DWORD dwSize = MAX_PATH;
  QueryFullProcessImageNameW(hProcess, 0, path, &dwSize);
  CloseHandle(hProcess);
}

std::wstring GetCommand() {
  std::vector<std::wstring> args;

  int originArgsLen;
  LPWSTR *originArgs = CommandLineToArgvW(GetCommandLineW(), &originArgsLen);

  // Keep argv[0]
  args.push_back(originArgs[0]);

  // Custom switches first, enable to override from terminal
  // args.push_back(L"--user-data-dir=\"User Data Test\""); // TODO: absolute
  args.push_back(L"--user-data-dir=\"User Data\""); // TODO: absolute
  args.push_back(L"--force-local-ntp");
  args.push_back(L"--enable-features=OverlayScrollbar");
  args.push_back(L"--disable-features=RendererCodeIntegrity,ReadLater");

  // Keep original args, skip argv[0]
  for (int i = 1; i < originArgsLen; i++)
    args.push_back(originArgs[i]);
  LocalFree(originArgs);

  std::wstring commandLine;
  for (auto a : args) {
    // Add quotes if needed
    bool quotes = (a[0] != '"') &&                     // No quote at begin
                  (*--a.end() != '"') &&               // No quote at end
                  (a.find(' ') != std::wstring::npos); // Has spaces
    commandLine += quotes ? L'"' + a + L'"' : a;
    commandLine += L' ';
  }
  return commandLine;
}

HANDLE FirstRun = {0};
bool IsFirstRun() {
  const wchar_t *uuid = L"{56A17F97-9F89-4926-8415-446649F25EB5}";
  FirstRun = CreateMutexW(NULL, TRUE, uuid);
  return GetLastError() == ERROR_SUCCESS;
}

void CustomCommand(const wchar_t *exePath, bool first_run) {
  STARTUPINFOW startInfo = {0};
  PROCESS_INFORMATION procInfo = {0};
  startInfo.cb = sizeof(STARTUPINFO);

  std::wstring commandLine = GetCommand();

  BOOL result =
      CreateProcessW(exePath, (LPWSTR)commandLine.c_str(), NULL, NULL, false,
                     CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT |
                         CREATE_DEFAULT_ERROR_MODE,
                     NULL, 0, &startInfo, &procInfo);
  AssertMsg(result, "CreateProcessW - CustomCommand - failed");

  if (first_run) {
    WaitForSingleObject(procInfo.hProcess, INFINITE);
    CloseHandle(FirstRun);
  }

  CloseHandle(procInfo.hProcess);
  CloseHandle(procInfo.hThread);

  ExitProcess(0);
}

typedef int (*EntryFn)();
EntryFn OriginEntry = NULL;

int Loader() {
  wchar_t exePath[MAX_PATH];
  GetModuleFileNameW(NULL, exePath, MAX_PATH);
  MakePortable();
  wchar_t parentPath[MAX_PATH];
  GetParentPath(parentPath);
  if (_wcsicmp(parentPath, exePath) != 0) {
    // Parent process is not chromium
    bool first_run = IsFirstRun();
    CustomCommand(exePath, first_run);
  }
  return OriginEntry(); // Return to origin entry
}

BOOL WINAPI DllMain(HINSTANCE _hinstDLL, DWORD fdwReason, LPVOID _lpReserved) {
  if (fdwReason != DLL_PROCESS_ATTACH) {
    return TRUE;
  }

  MODULEINFO info = {0};
  GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &info,
                       sizeof(MODULEINFO));
  LPVOID entry = info.EntryPoint;
  MH_Initialize();
  MH_CreateHook(entry, (LPVOID)Loader, (LPVOID *)&OriginEntry);
  MH_EnableHook(entry);
  return TRUE;
}
