@echo off
echo ================================================
echo    User Management System with Ngrok
echo ================================================
echo.

echo 🔧 Setting up environment...
set ASPNETCORE_ENVIRONMENT=Development
set ASPNETCORE_URLS=https://192.168.31.8:7272
set ASPNETCORE_HTTPS_PORT=7272

echo 📋 Environment Variables:
echo    ASPNETCORE_ENVIRONMENT=%ASPNETCORE_ENVIRONMENT%
echo    ASPNETCORE_URLS=%ASPNETCORE_URLS%
echo    ASPNETCORE_HTTPS_PORT=%ASPNETCORE_HTTPS_PORT%
echo.

echo 🏗️ Building application...
dotnet build -c Release
if %ERRORLEVEL% neq 0 (
    echo ❌ Build failed!
    pause
    exit /b 1
)

echo ✅ Build successful!
echo.

echo 🚀 Starting application with Ngrok...
echo 📡 Your application will be accessible via:
echo    - Local: https://192.168.31.8:7272
echo    - Ngrok tunnel: Check console output for public URL
echo    - Ngrok dashboard: http://localhost:4040
echo.
echo 🔑 Admin credentials: admin@gmail.com / 123
echo.
echo 📊 Useful endpoints:
echo    - Health check: /health
echo    - Ngrok test: /test-ngrok
echo.
echo 💡 Press Ctrl+C to stop the application
echo ================================================
echo.

dotnet run

pause