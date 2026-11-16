@echo off
title N976N SEC76 EXP9 - startup fallback
echo [Stage 0] N976N SEC76 EXP9 stock WinPE touch demo
echo Starting native display. This console remains if the app cannot run.
if not exist "X:\N976nTouchDemo\N976nTouchDemo.exe" goto missing
start "" /wait "X:\N976nTouchDemo\N976nTouchDemo.exe" --pe-start
set "N976N_DEMO_EXIT=%errorlevel%"
goto finished
:missing
echo Native executable is missing.
set "N976N_DEMO_EXIT=2"
:finished
echo Native demo returned: %N976N_DEMO_EXIT%
if exist X:\N976nTouchDemo\startup.log type X:\N976nTouchDemo\startup.log
echo This prompt remains available. No reboot or retry was requested.
exit /b %N976N_DEMO_EXIT%
