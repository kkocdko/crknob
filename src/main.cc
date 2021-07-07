#include "MinHook.h"
#include "patch.cc"
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
