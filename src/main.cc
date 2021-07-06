#include "MinHook.h"
#include "patch.cc"
#include <corecrt.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <windows.h>
#include <winnt.h>

#ifdef _WIN64
typedef uint64_t MWORD;
#else
typedef uint32_t MWORD;
#endif

void AssertMsg(bool condition, std::string msg) {
  if (!condition) {
    MessageBox(NULL, msg.c_str(), "ERROR", MB_OK);
    exit(1);
  }
}

typedef struct {
  MWORD ExitStatus;
  MWORD PebBaseAddress;
  MWORD AffinityMask;
  MWORD BasePriority;
  MWORD UniqueProcessId;
  MWORD InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS(WINAPI *FnNtQueryInformationProcess)(HANDLE, UINT, PVOID,
                                                      ULONG, PULONG);
DWORD GetParentProcessID() {
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

bool GetParentPath(wchar_t *path) {
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                GetParentProcessID());
  if (hProcess) {
    DWORD dwSize = MAX_PATH;
    bool ret = QueryFullProcessImageNameW(hProcess, 0, path, &dwSize) != 0;

    CloseHandle(hProcess);
    return ret;
  }

  return false;
}

std::wstring GetCommand(const wchar_t *exeFolder) {
  std::vector<std::wstring> args;

  int originArgsLen;
  LPWSTR *originArgs = CommandLineToArgvW(GetCommandLineW(), &originArgsLen);

  // Keep argv[0]
  args.push_back(originArgs[0]);

  // Custom switches first, enable to override from terminal
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
                  (*(--a.end()) != '"') &&             // No quote at end
                  (a.find(' ') != std::wstring::npos); // Has spaces
    commandLine += quotes ? L'"' + a + L'"' : a;
    commandLine += L' ';
  }
  return commandLine;
}

HANDLE FirstRun;
bool IsFirstRun() {
  const wchar_t *uuid = L"{56A17F97-9F89-4926-8415-446649F25EB5}";
  FirstRun = CreateMutexW(NULL, TRUE, uuid);
  return GetLastError() == ERROR_SUCCESS;
}

// 自定义启动参数
void CustomCommand(const wchar_t *exeFolder, const wchar_t *exePath,
                   bool first_run) {
  std::vector<HANDLE> program_handles;
  // if (first_run) {
  //   // 启动时运行
  //   LaunchAtStart(iniPath, exeFolder, program_handles);
  // }

  // 启动进程
  STARTUPINFOW startInfo = {0};
  PROCESS_INFORMATION procInfo = {0};
  startInfo.cb = sizeof(STARTUPINFO);

  // 根据配置文件插入额外的命令行参数
  std::wstring commandLine = GetCommand(exeFolder);

  BOOL result =
      CreateProcessW(exePath, (LPWSTR)commandLine.c_str(), NULL, NULL, false,
                     CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT |
                         CREATE_DEFAULT_ERROR_MODE,
                     NULL, 0, &startInfo, &procInfo);
  AssertMsg(result, "CreateProcessW failed");

  if (first_run) {
    WaitForSingleObject(procInfo.hProcess, INFINITE);

    // 释放句柄
    CloseHandle(FirstRun);

    // 结束时运行
    // LaunchAtEnd(iniPath, exeFolder);
  }

  CloseHandle(procInfo.hProcess);
  CloseHandle(procInfo.hThread);

  ExitProcess(0);
}

typedef int (*EntryFn)();
EntryFn OriginEntry = NULL;

int Loader() {
  wchar_t exePath[MAX_PATH];
  wchar_t exeDir[MAX_PATH];
  GetModuleFileNameW(NULL, exePath, MAX_PATH);
  _wsplitpath(exePath, nullptr, exeDir, nullptr, nullptr);

  MakePortable();

  wchar_t parentPath[MAX_PATH];
  GetParentPath(parentPath);
  if (_wcsicmp(parentPath, exePath) != 0) {
    // Parent process is not chromium
    bool first_run = IsFirstRun();
    CustomCommand(exeDir, exePath, first_run);
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
