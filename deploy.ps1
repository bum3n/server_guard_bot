param(
    [string[]]$Files = @("config.py", "main.py", "vpn_manager.py", "analyzer.py", "backup_manager.py", "card_generator.py", "metrics_store.py", "security_tools.py", "maintenance.py")
)

$ErrorActionPreference = "Stop"
$Server = "$($env:SERVER_SSH ?? "root@YOUR_SERVER_IP")"
$RemoteDir = "/root/server_guard"
$TmpDir = "$RemoteDir/.deploy_tmp"

Write-Host "[1/5] Local syntax check..." -ForegroundColor Cyan
foreach ($f in $Files) {
    if (-not (Test-Path $f)) { throw "File not found: $f" }
    python -m py_compile $f
    if ($LASTEXITCODE -ne 0) { throw "Syntax error in $f" }
}

Write-Host "[2/5] Upload to temp dir..." -ForegroundColor Cyan
ssh $Server "rm -rf $TmpDir && mkdir -p $TmpDir"
scp $Files "${Server}:$TmpDir/"
if ($LASTEXITCODE -ne 0) { throw "scp failed" }

Write-Host "[3/5] Remote syntax check..." -ForegroundColor Cyan
ssh $Server "cd $TmpDir && python3 -m py_compile *.py"
if ($LASTEXITCODE -ne 0) { throw "Remote syntax check failed, nothing replaced" }

Write-Host "[4/5] Replace files and restart..." -ForegroundColor Cyan
ssh $Server "rm -rf $TmpDir/__pycache__ && cp $TmpDir/*.py $RemoteDir/ && rm -rf $TmpDir && systemctl restart server_guard"

Write-Host "[5/5] Status check..." -ForegroundColor Cyan
Start-Sleep -Seconds 4
$status = (ssh $Server "systemctl is-active server_guard").Trim()
if ($status -eq "active") {
    Write-Host "OK: server_guard is active" -ForegroundColor Green
} else {
    Write-Host "FAIL: server_guard is $status" -ForegroundColor Red
    ssh $Server "journalctl -u server_guard -n 30 --no-pager"
    exit 1
}

