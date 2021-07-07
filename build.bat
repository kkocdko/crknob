@echo off
rd /s /q build >nul
md build
cd build
:: cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release ..
cmake -G "Ninja" ..
ninja
:: strip libcrknob.dll
cd ..
