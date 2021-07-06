#include <iostream>
#include <windows.h>
using namespace std;
int main() {
  wchar_t *exePath = (wchar_t *)_pgmptr;
  wchar_t *exeDir = (wchar_t *)calloc(wcslen(exePath), sizeof(wchar_t));
  _wsplitpath(exePath, nullptr, exeDir, nullptr, nullptr);
  cout << _pgmptr << endl;
  cout << exeDir << endl;
  return 0;
}