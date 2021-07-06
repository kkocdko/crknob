<div align="center">
<h1>crknob</h1>
<p>Simple tool for chromium on windows.</p>
<img src="https://flat.badgen.net/github/release/kkocdko/crknob?color=4caf50">
<img src="https://flat.badgen.net/github/license/kkocdko/crknob?color=4caf50">
</div>

> Thanks to [GreenChrome](https://github.com/shuax/GreenChrome).

### Warning

This project is still developing.

### Todo List

0. BUG: open file by explorer when the browser is already running, `CreateProcessW` failed?

1. Clean code.

### Build

```batch
rd /s /q build && md build && cd build && cmake -G "Ninja" .. && ninja
```
