@echo off
rem CodeShield 一键启动（使用本机已装 PySide6 的系统 Python 3.11）
title CodeShield - 代码敏感信息扫描器
cd /d "%~dp0"
E:\Python3.11.0\python.exe main.py
if errorlevel 1 pause
