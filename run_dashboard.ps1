# AutoThreat Dashboard launcher (Windows)
Set-Location $PSScriptRoot

$VenvPython = "C:\atvenv\Scripts\python.exe"
$UseVenv = Test-Path $VenvPython

Write-Host ""
Write-Host "  AutoThreat v3.0 — Dashboard Launcher" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python not found." -ForegroundColor Red
    exit 1
}

function Test-Streamlit($Py) {
    & $Py -c "import streamlit; print(streamlit.__version__)" 2>$null
    return $LASTEXITCODE -eq 0
}

$Python = if ($UseVenv) { $VenvPython } else { "python" }

if (-not (Test-Streamlit $Python)) {
    Write-Host "[SETUP] First-time setup — creating venv at C:\atvenv (short path for Windows)..." -ForegroundColor Yellow
    if (-not (Test-Path C:\atvenv)) {
        # Python 3.12 — avoids numpy OverflowError on Python 3.13
        py -3.12 -m venv C:\atvenv
    }
    & C:\atvenv\Scripts\python.exe -m pip install --upgrade pip
    & C:\atvenv\Scripts\pip.exe install -r requirements.txt --default-timeout=600
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "[ERROR] Install failed (network or permissions)." -ForegroundColor Red
        Write-Host "  Option A: Retry when internet is stable:" -ForegroundColor Yellow
        Write-Host "    C:\atvenv\Scripts\pip install -r requirements.txt" -ForegroundColor Gray
        Write-Host "  Option B: Use Docker (start Docker Desktop first):" -ForegroundColor Yellow
        Write-Host "    docker-compose up -d --build" -ForegroundColor Gray
        exit 1
    }
    $Python = $VenvPython
}

Write-Host "[OK] Dashboard → http://localhost:8501  (Ctrl+C to stop)" -ForegroundColor Green
Write-Host ""
& $Python -m streamlit run dashboard/app.py --server.port 8501 --server.address localhost
