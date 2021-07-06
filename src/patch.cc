#include "MinHook.h"
#include <windows.h>

wchar_t user_data_path[MAX_PATH];

typedef BOOL(WINAPI *pSHGetFolderPath)(_In_ HWND hwndOwner, _In_ int nFolder,
                                       _In_ HANDLE hToken, _In_ DWORD dwFlags,
                                       _Out_ LPTSTR pszPath);

pSHGetFolderPath RawSHGetFolderPath = NULL;

BOOL WINAPI MyCryptProtectData(
    _In_ DATA_BLOB *pDataIn, _In_opt_ LPCWSTR szDataDescr,
    _In_opt_ DATA_BLOB *pOptionalEntropy, _Reserved_ PVOID pvReserved,
    _In_opt_ CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct, _In_ DWORD dwFlags,
    _Out_ DATA_BLOB *pDataOut) {
  pDataOut->cbData = pDataIn->cbData;
  pDataOut->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, pDataOut->cbData);
  memcpy(pDataOut->pbData, pDataIn->pbData, pDataOut->cbData);
  return true;
}

typedef BOOL(WINAPI *pCryptUnprotectData)(
    _In_ DATA_BLOB *pDataIn, _Out_opt_ LPWSTR *ppszDataDescr,
    _In_opt_ DATA_BLOB *pOptionalEntropy, _Reserved_ PVOID pvReserved,
    _In_opt_ CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct, _In_ DWORD dwFlags,
    _Out_ DATA_BLOB *pDataOut);

pCryptUnprotectData RawCryptUnprotectData = NULL;

BOOL WINAPI MyCryptUnprotectData(
    _In_ DATA_BLOB *pDataIn, _Out_opt_ LPWSTR *ppszDataDescr,
    _In_opt_ DATA_BLOB *pOptionalEntropy, _Reserved_ PVOID pvReserved,
    _In_opt_ CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct, _In_ DWORD dwFlags,
    _Out_ DATA_BLOB *pDataOut) {
  if (RawCryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy,
                            pvReserved, pPromptStruct, dwFlags, pDataOut)) {
    return true;
  }

  pDataOut->cbData = pDataIn->cbData;
  pDataOut->pbData = (BYTE *)LocalAlloc(LMEM_FIXED, pDataOut->cbData);
  memcpy(pDataOut->pbData, pDataIn->pbData, pDataOut->cbData);
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

// Fake `GetComputerNameW` and `GetVolumeInformationW`
// Src: chromium/rlz/win/lib/machine_id_win.cc
void MakePortable() {
  HMODULE kernel32 = LoadLibraryW(L"kernel32.dll");
  if (kernel32) {
    PBYTE GetComputerNameW =
        (PBYTE)GetProcAddress(kernel32, "GetComputerNameW");
    PBYTE GetVolumeInformationW =
        (PBYTE)GetProcAddress(kernel32, "GetVolumeInformationW");

    MH_STATUS status = MH_CreateHook((LPVOID)GetComputerNameW,
                                     (LPVOID)FakeGetComputerName, NULL);
    if (status == MH_OK) {
      MH_EnableHook(GetComputerNameW);
    } else {
      // DebugLog(L"MH_CreateHook GetComputerNameW failed:%d", status);
    }
    status = MH_CreateHook((LPVOID)GetVolumeInformationW,
                           (LPVOID)FakeGetVolumeInformation, NULL);
    if (status == MH_OK) {
      MH_EnableHook(GetVolumeInformationW);
    } else {
      // DebugLog(L"MH_CreateHook GetVolumeInformationW failed:%d", status);
    }
  }

  // components/os_crypt/os_crypt_win.cc
  HMODULE Crypt32 = LoadLibraryW(L"Crypt32.dll");
  if (Crypt32) {
    PBYTE CryptProtectData = (PBYTE)GetProcAddress(Crypt32, "CryptProtectData");
    PBYTE CryptUnprotectData =
        (PBYTE)GetProcAddress(Crypt32, "CryptUnprotectData");

    MH_STATUS status = MH_CreateHook((LPVOID)CryptProtectData,
                                     (LPVOID)MyCryptProtectData, NULL);
    if (status == MH_OK) {
      MH_EnableHook(CryptProtectData);
    } else {
      // DebugLog(L"MH_CreateHook CryptProtectData failed:%d", status);
    }
    status =
        MH_CreateHook((LPVOID)CryptUnprotectData, (LPVOID)MyCryptUnprotectData,
                      (LPVOID *)&RawCryptUnprotectData);
    if (status == MH_OK) {
      MH_EnableHook(CryptUnprotectData);
    } else {
      // DebugLog(L"MH_CreateHook CryptUnprotectData failed:%d", status);
    }
  }
}
