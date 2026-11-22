@echo off
setlocal
set "PATH=C:\Users\%USERNAME%\AppData\Local\Python\bin;%PATH%"
python -m log_detective.cli %*
