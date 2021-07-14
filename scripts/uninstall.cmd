@echo off

set PLUGIN_NAME=tagada
set IDA_DIR="C:\ida"
set PLUGINS_DIR=%IDA_DIR%\plugins
set ROOT_DIR=%~dp0..

del   %PLUGINS_DIR%\%PLUGIN_NAME%.py
rmdir %PLUGINS_DIR%\%PLUGIN_NAME%
