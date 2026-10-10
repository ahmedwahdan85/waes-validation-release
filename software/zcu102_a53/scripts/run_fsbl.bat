@echo off
call C:\AMDDesignTools\2025.2\Vitis\settings64.bat
cd /d %~dp0..
xsdb scripts\run_fsbl.tcl
