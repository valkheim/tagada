@echo off

set PLUGIN_NAME=tagada
set IDA_DIR="C:\ida"
set PLUGINS_DIR=%IDA_DIR%\plugins
set ROOT_DIR=%~dp0..

mklink       %PLUGINS_DIR%\%PLUGIN_NAME%.py %ROOT_DIR%\%PLUGIN_NAME%.py
mklink /J /D %PLUGINS_DIR%\%PLUGIN_NAME%    %ROOT_DIR%\%PLUGIN_NAME%
