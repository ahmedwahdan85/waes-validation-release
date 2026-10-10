@echo off
call C:\AMDDesignTools\2025.2\Vitis\settings64.bat
cd /d %~dp0..
vitis -s scripts\make_platform.py > ws_platform.log 2>&1
