#include "MinHook.h"
#include <windows.h>

wchar_t user_data_path[MAX_PATH];

typedef BOOL(WINAPI *pSHGetFolderPath)(_In_ HWND hwndOwner, _In_ int nFolder,
                                       _In_ HANDLE hToken, _In_ DWORD dwFlags,
                                       _Out_ LPTSTR pszPath);

pSHGetFolderPath RawSHGetFolderPath = NULL;

BOOL WINAPI MySHGetFolderPath(_In_ HWND hwndOwner, _In_ int nFolder,
                              _In_ HANDLE hToken, _In_ DWORD dwFlags,
                              _Out_ LPTSTR pszPath) {
  BOOL result =
      RawSHGetFolderPath(hwndOwner, nFolder, hToken, dwFlags, pszPath);
  if (nFolder == CSIDL_LOCAL_APPDATA) {
    // 用户数据路径
    wcscpy(pszPath, user_data_path);
  }

  return result;
}

typedef struct _CRYPTOAPI_BLOB {
  DWORD cbData;
  BYTE *pbData;
} CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB, CRYPT_UINT_BLOB, *PCRYPT_UINT_BLOB,
    CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB, CERT_NAME_BLOB, CERT_RDN_VALUE_BLOB,
    *PCERT_NAME_BLOB, *PCERT_RDN_VALUE_BLOB, CERT_BLOB, *PCERT_BLOB, CRL_BLOB,
    *PCRL_BLOB, DATA_BLOB, *PDATA_BLOB, CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB,
    CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB, CRYPT_DIGEST_BLOB, *PCRYPT_DIGEST_BLOB,
    CRYPT_DER_BLOB, PCRYPT_DER_BLOB, CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB;

typedef struct _CRYPTPROTECT_PROMPTSTRUCT {
  DWORD cbSize;
  DWORD dwPromptFlags;
  HWND hwndApp;
  LPCWSTR szPrompt;
} CRYPTPROTECT_PROMPTSTRUCT, *PCRYPTPROTECT_PROMPTSTRUCT;

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

BOOL WINAPI FakeGetComputerName(_Out_ LPTSTR lpBuffer,
                                _Inout_ LPDWORD lpnSize) {
  return 0;
}

BOOL WINAPI FakeGetVolumeInformation(_In_opt_ LPCTSTR lpRootPathName,
                                     _Out_opt_ LPTSTR lpVolumeNameBuffer,
                                     _In_ DWORD nVolumeNameSize,
                                     _Out_opt_ LPDWORD lpVolumeSerialNumber,
                                     _Out_opt_ LPDWORD lpMaximumComponentLength,
                                     _Out_opt_ LPDWORD lpFileSystemFlags,
                                     _Out_opt_ LPTSTR lpFileSystemNameBuffer,
                                     _In_ DWORD nFileSystemNameSize) {
  return 0;
}

// 不让chrome使用GetComputerNameW，GetVolumeInformationW
// chromium/rlz/win/lib/machine_id_win.cc
void MakePortable(const wchar_t *iniPath) {
  HMODULE kernel32 = LoadLibraryW(L"kernel32.dll");
  if (kernel32) {
    PBYTE GetComputerNameW =
        (PBYTE)GetProcAddress(kernel32, "GetComputerNameW");
    PBYTE GetVolumeInformationW =
        (PBYTE)GetProcAddress(kernel32, "GetVolumeInformationW");

    MH_STATUS status =
        MH_CreateHook(GetComputerNameW, FakeGetComputerName, NULL);
    if (status == MH_OK) {
      MH_EnableHook(GetComputerNameW);
    } else {
      DebugLog(L"MH_CreateHook GetComputerNameW failed:%d", status);
    }
    status =
        MH_CreateHook(GetVolumeInformationW, FakeGetVolumeInformation, NULL);
    if (status == MH_OK) {
      MH_EnableHook(GetVolumeInformationW);
    } else {
      DebugLog(L"MH_CreateHook GetVolumeInformationW failed:%d", status);
    }
  }

  // components/os_crypt/os_crypt_win.cc
  HMODULE Crypt32 = LoadLibraryW(L"Crypt32.dll");
  if (Crypt32) {
    PBYTE CryptProtectData = (PBYTE)GetProcAddress(Crypt32, "CryptProtectData");
    PBYTE CryptUnprotectData =
        (PBYTE)GetProcAddress(Crypt32, "CryptUnprotectData");

    MH_STATUS status =
        MH_CreateHook(CryptProtectData, MyCryptProtectData, NULL);
    if (status == MH_OK) {
      MH_EnableHook(CryptProtectData);
    } else {
      DebugLog(L"MH_CreateHook CryptProtectData failed:%d", status);
    }
    status = MH_CreateHook(CryptUnprotectData, MyCryptUnprotectData,
                           (LPVOID *)&RawCryptUnprotectData);
    if (status == MH_OK) {
      MH_EnableHook(CryptUnprotectData);
    } else {
      DebugLog(L"MH_CreateHook CryptUnprotectData failed:%d", status);
    }
  }
}
