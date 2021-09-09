# crknob

[![CI](https://img.shields.io/github/workflow/status/kkocdko/crknob/CI?color=08c)](https://github.com/kkocdko/crknob/actions)
[![Download](https://img.shields.io/github/downloads/kkocdko/crknob/total?color=08c)](https://github.com/kkocdko/crknob/releases#:~:text=Assets)
[![License](https://img.shields.io/github/license/kkocdko/crknob?color=08c)](LICENSE)

Chromium portable patch on windows.

## Build

```batch
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -C build
```

Then attach the DLL file by [setdll](https://github.com/Microsoft/Detours/tree/master/samples/setdll).

## Alternative

[GreenChrome](https://github.com/shuax/GreenChrome), this program's predecessor, more functions.

## Contributing

Follow [clang-format](https://clang.llvm.org/docs/ClangFormat.html) and winapi style identifier naming rules.
