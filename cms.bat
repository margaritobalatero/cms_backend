@echo off

:: Launch backend server (Node.js)
start "Backend Server" cmd /k "cd /d D:\cms && node server.js"

:: Launch frontend server (npm start)
start "Frontend Server" cmd /k "cd /d D:\cms\client && npm start"
