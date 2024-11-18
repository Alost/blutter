@echo off
%1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit
cd /d "%~dp0"

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set checkFilePath="./bin/icuuc73.dll"
if not exist "%checkFilePath%" (
    python scripts\init_env_win.py
)

rm -rf output\lib\arm64-v8a
mkdir output\lib\arm64-v8a
python blutter.py ./input/lib/arm64-v8a ./output/lib/arm64-v8a/

pause
