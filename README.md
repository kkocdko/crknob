# crknob

[![CI](https://img.shields.io/github/workflow/status/kkocdko/crknob/CI?color=2a4)](https://github.com/kkocdko/crknob/actions)
[![Download](https://img.shields.io/github/downloads/kkocdko/crknob/total?color=2a4)](https://github.com/kkocdko/crknob/releases#:~:text=Assets)
[![License](https://img.shields.io/github/license/kkocdko/crknob?color=2a4)](LICENSE)

Chrome portable patch on windows.

## Usage

```batch
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -C build
```

Then attach `crknob.dll` to `chrome.exe` with [setdll](https://github.com/Microsoft/Detours/tree/master/samples/setdll).

## Alternative

[GreenChrome](https://github.com/shuax/GreenChrome), this program's predecessor, more functions.

## Contributing

Follow [clang-format](https://clang.llvm.org/docs/ClangFormat.html) and winapi style identifier naming rules.
