@echo off
rd /s /q build
md build
cd build
:: cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release ..
cmake -G "Ninja" ..
ninja
cd ..
