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

inline std::wstring QuotePathIfNeeded(const std::wstring &path) {
  std::vector<wchar_t> buffer(path.length() + 1 /* null */ + 2 /* quotes */);
  wcscpy(&buffer[0], path.c_str());

  PathQuoteSpaces((LPSTR)&buffer[0]); // TODO: impl self

  return std::wstring(&buffer[0]);
}

std::wstring GetCommand(const wchar_t *exeFolder) {
  std::vector<std::wstring> command_line;

  int nArgs;
  LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);

  // Keep argv[0]
  command_line.push_back(szArglist[0]);

  // Custom switches first, enable to override from terminal
  command_line.push_back(L"--user-data-dir=\"User Data\""); // TODO: absolute
  command_line.push_back(L"--force-local-ntp");
  command_line.push_back(L"--enable-features=OverlayScrollbar");
  command_line.push_back(L"--disable-features=RendererCodeIntegrity,ReadLater");

  // Keep original args, skip argb[0]
  for (int i = 1; i < nArgs; i++)
    command_line.push_back(QuotePathIfNeeded(szArglist[i]));
  LocalFree(szArglist);

  std::wstring my_command_line;
  for (auto str : command_line) {
    my_command_line += str;
    my_command_line += L" ";
  }

  return my_command_line;
}

HANDLE FirstRun;
bool IsFirstRun() {
  bool first_run = false;
  FirstRun =
      CreateMutexW(NULL, TRUE, L"{56A17F97-9F89-4926-8415-446649F25EB5}");
  if (GetLastError() == ERROR_SUCCESS) {
    first_run = true;
  }

  return first_run;
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
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  si.cb = sizeof(STARTUPINFO);

  // 根据配置文件插入额外的命令行参数
  std::wstring my_command_line = GetCommand(exeFolder);

  BOOL s = CreateProcessW(exePath, (LPWSTR)my_command_line.c_str(), NULL, NULL,
                          false,
                          CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT |
                              CREATE_DEFAULT_ERROR_MODE,
                          NULL, 0, &si, &pi);
  AssertMsg(s, "CreateProcessW failed");

  if (first_run) {
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 释放句柄
    CloseHandle(FirstRun);

    // 结束时运行
    // LaunchAtEnd(iniPath, exeFolder);
  }

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  ExitProcess(0);
}

HMODULE hInstance;
typedef int (*Startup)();
Startup OriginEntry = NULL;

int Loader() {
  const size_t MAX_LONGPATH = 2 * MAX_PATH;
  // Could not use `_pgmptr` in DLL
  wchar_t exePath[MAX_LONGPATH]; // Mitigating errors caused by long path
  wchar_t exeDir[MAX_LONGPATH];
  GetModuleFileNameW(NULL, exePath, MAX_LONGPATH);
  _wsplitpath(exePath, nullptr, exeDir, nullptr, nullptr);

  MakePortable();

  // 父进程不是Chrome，则需要启动追加参数功能
  wchar_t parentPath[MAX_LONGPATH];
  GetParentPath(parentPath);
  if (_wcsicmp(parentPath, exePath) != 0) {
    // MessageBoxA(NULL, "Once", "LPCSTR lpCaption", MB_OK);
    // if (PathFileExistsW(parentPath) && _wcsicmp(parentPath, exePath) != 0)
    // { 启动单次功能
    bool first_run = IsFirstRun();
    CustomCommand(exeDir, exePath, first_run);
  }
  // Return to origin
  return OriginEntry();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  if (fdwReason != DLL_PROCESS_ATTACH)
    return TRUE; // Skip
  hInstance = hinstDLL;

  MODULEINFO moduleInfo = {0};
  GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &moduleInfo,
                       sizeof(MODULEINFO));
  LPVOID entry = moduleInfo.EntryPoint;
  MH_Initialize();
  MH_CreateHook(entry, (LPVOID)Loader, (LPVOID *)&OriginEntry);
  MH_EnableHook(entry);
  return TRUE;
}
