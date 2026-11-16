@echo off
cd /d "%~dp0"
echo Open an Administrator command prompt for live capture.
echo Use a NEW result folder, for example:
echo N976nUfsTrace.exe session results\run01
echo Offline: N976nUfsTrace.exe diff results\run01\before.bin results\run01\after.bin
echo Text: type results\run01\result.txt
cmd /k
