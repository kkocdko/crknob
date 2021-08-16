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

- Absolute `User Data` path, enable to call from other directory.

- Fit [minhook - 4a45552](https://github.com/TsudaKageyu/minhook/commit/4a45552)?

### Usage

```batch
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -C build
```

Then attach the DLL file by [setdll](https://github.com/Microsoft/Detours/tree/master/samples/setdll).

### Contributing

Follow [clang-format](https://clang.llvm.org/docs/ClangFormat.html) and winapi style identifier naming rules.
