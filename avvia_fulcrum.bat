@echo off
title Avvio Fulcrum Electrum Server
echo Avvio di Fulcrum in corso...
E:\fulcrum\Fulcrum.exe E:\fulcrum\fulcrum.conf
if %errorlevel% neq 0 (
    echo.
    echo Errore durante l'esecuzione di Fulcrum.
)
pause
