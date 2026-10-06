# PowerShell Service Management Script for Zaalima Security Gateway
Param(
    [string]$Action = "status" # Choices: install-nssm, install-task, start, stop, restart, status, logs, remove
)

$ServiceName = "ZaalimaSecurityGateway"
$ProjectDir = "c:\Users\Dharma Teja\OneDrive\Desktop\Ai Security\enterprise-llm-security-gateway"
$PythonExe = "$ProjectDir\venv\Scripts\python.exe"
$LogDir = "$ProjectDir\logs"
$StdoutLog = "$LogDir\backend_stdout.log"
$StderrLog = "$LogDir\backend_stderr.log"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

switch ($Action.ToLower()) {
    "install-nssm" {
        Write-Host "Installing Windows Service via NSSM..." -ForegroundColor Green
        nssm install $ServiceName "$PythonExe" "-m uvicorn app.main:app --host 127.0.0.1 --port 8081"
        nssm set $ServiceName AppDirectory "$ProjectDir"
        nssm set $ServiceName AppStdout "$StdoutLog"
        nssm set $ServiceName AppStderr "$StderrLog"
        nssm set $ServiceName Start SERVICE_AUTO_START
        nssm set $ServiceName AppExit Default Restart
        nssm start $ServiceName
        Write-Host "Service $ServiceName installed and started successfully!" -ForegroundColor Green
    }
    "install-task" {
        Write-Host "Registering Windows Startup Task..." -ForegroundColor Green
        $ActionScript = New-ScheduledTaskAction -Execute "$ProjectDir\run_backend_service.bat" -WorkingDirectory "$ProjectDir"
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $ServiceName -Action $ActionScript -Trigger $Trigger -Settings $Settings -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force
        Start-ScheduledTask -TaskName $ServiceName
        Write-Host "Task $ServiceName registered and started!" -ForegroundColor Green
    }
    "start" {
        if (Get-Command nssm -ErrorAction SilentlyContinue) {
            nssm start $ServiceName
        } else {
            Start-ScheduledTask -TaskName $ServiceName
        }
    }
    "stop" {
        if (Get-Command nssm -ErrorAction SilentlyContinue) {
            nssm stop $ServiceName
        } else {
            Stop-ScheduledTask -TaskName $ServiceName
        }
    }
    "restart" {
        if (Get-Command nssm -ErrorAction SilentlyContinue) {
            nssm restart $ServiceName
        } else {
            Stop-ScheduledTask -TaskName $ServiceName
            Start-Sleep -Seconds 2
            Start-ScheduledTask -TaskName $ServiceName
        }
    }
    "status" {
        Write-Host "Checking service status..." -ForegroundColor Cyan
        try {
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:8081/health" -ErrorAction Stop
            Write-Host "Gateway HTTP Status: ONLINE" -ForegroundColor Green
            Write-Host "Health check response: $($response | ConvertTo-Json -Compress)"
        } catch {
            Write-Host "Gateway HTTP Status: OFFLINE or UNREACHABLE" -ForegroundColor Red
            Write-Host "Error: $_"
        }
    }
    "logs" {
        Write-Host "--- STDOUT LOG ---" -ForegroundColor Yellow
        if (Test-Path $StdoutLog) { Get-Content $StdoutLog -Tail 20 }
        Write-Host "--- STDERR LOG ---" -ForegroundColor Red
        if (Test-Path $StderrLog) { Get-Content $StderrLog -Tail 20 }
    }
    "remove" {
        if (Get-Command nssm -ErrorAction SilentlyContinue) {
            nssm stop $ServiceName
            nssm remove $ServiceName confirm
        } else {
            Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
        }
        Write-Host "Service $ServiceName removed." -ForegroundColor Yellow
    }
    Default {
        Write-Host "Usage: .\setup_windows_service.ps1 -Action [install-nssm | install-task | start | stop | restart | status | logs | remove]"
    }
}
