#include "MinHook.h"
#include <psapi.h>
#include <stdint.h>
#include <windows.h>

#ifdef _WIN64
typedef uint64_t MWORD;
#else
typedef uint32_t MWORD;
#endif

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

void GreenChrome() {
  wchar_t *exePath = (wchar_t *)_pgmptr;
  wchar_t *exeDir = (wchar_t *)calloc(wcslen(exePath), sizeof(wchar_t));
  _wsplitpath(exePath, nullptr, exeDir, nullptr, nullptr);

  // 自定义用户数据目录
  //   CustomUserData(iniPath);

  // 打造便携版chrome
  //   MakePortable(iniPath);

  // 父进程不是Chrome，则需要启动追加参数功能
  wchar_t parentPath[MAX_PATH];
  if (GetParentPath(parentPath)) {
    if (_wcsicmp(parentPath, exePath) != 0) {
      // if (PathFileExistsW(parentPath) && _wcsicmp(parentPath, exePath) != 0)
      // { 启动单次功能
      bool first_run = OnceFeature(iniPath);
      CustomCommand(iniPath, exeFolder, exePath, first_run);
    }
  } else {
    // DebugLog(L"GetParentPath failed");
    exit(1);
  }
}

HMODULE hInstance;
typedef int (*Startup)();
Startup ChromeMain = NULL;

int Loader() {
  GreenChrome();

  //返回到Chrome
  //   ChromeMain();
  return ChromeMain();
}

void InstallLoader() {
  //获取程序入口点
  MODULEINFO mi;
  GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &mi,
                       sizeof(MODULEINFO));
  PBYTE entry = (PBYTE)mi.EntryPoint;

  // 入口点跳转到Loader
  MH_STATUS status =
      MH_CreateHook(entry, (LPVOID)Loader, (LPVOID *)&ChromeMain);
  if (status == MH_OK) {
    MH_EnableHook(entry);
  } else {
    // DebugLog(L"MH_CreateHook InstallLoader failed:%d", status);
    exit(1);
  }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  if (fdwReason != DLL_PROCESS_ATTACH)
    return TRUE;
  hInstance = hinstDLL;

  // 初始化HOOK库成功以后安装加载器
  MH_STATUS status = MH_Initialize();
  if (status == MH_OK) {
    InstallLoader();
  } else {
    // DebugLog(L"MH_Initialize failed:%d", status);
    exit(1);
  }
  return TRUE; // Successful DLL_PROCESS_ATTACH.
}

// =======================================
