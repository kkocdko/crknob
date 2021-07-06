#include "MinHook.h"
#include <windows.h>

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
