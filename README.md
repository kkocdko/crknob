<div align="center">
<h1>crknob</h1>
<p>Simple tool for chromium on windows.</p>
<img src="https://flat.badgen.net/github/release/kkocdko/crknob?color=4caf50">
<img src="https://flat.badgen.net/github/license/kkocdko/crknob?color=4caf50">
</div>

> Thanks to [GreenChrome](https://github.com/shuax/GreenChrome).

### Why

There are many features in GreenChrome that I don't need.

### Todo List

0. Absolute `User Data` path, enable to call from other directory.

### Usage

You need [CMake](https://cmake.org) and [Ninja](https://ninja-build.org), then run `build.bat`.

Use [setdll](https://github.com/Microsoft/Detours/tree/master/samples/setdll) to attach the DLL file:

```batch
cd /d %~dp0
if exist chrome.exe~ (
    del chrome.exe
    ren chrome.exe~ chrome.exe
)
setdll /d:libcrknob.dll chrome.exe
pause
```
