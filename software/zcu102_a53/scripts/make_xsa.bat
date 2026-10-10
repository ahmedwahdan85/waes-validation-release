@echo off
call C:\AMDDesignTools\2025.2\Vivado\settings64.bat
cd /d %~dp0..
vivado -mode batch -nojournal -log hw\make_xsa.log -source scripts\make_xsa.tcl
