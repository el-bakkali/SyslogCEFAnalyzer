# build-release.ps1 — Builds and packages Syslog/CEF Analyzer for GitHub Releases
$ErrorActionPreference = "Stop"
$Version = "2.0.0"
$ProjectPath = "src\SyslogCEFAnalyzer\SyslogCEFAnalyzer.csproj"
$OutputDir = "release"
$ZipName = "SyslogCEFAnalyzer-v$Version-win-x64.zip"

Write-Host "Building Syslog/CEF Analyzer v$Version..." -ForegroundColor Cyan

if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutputDir | Out-Null

dotnet publish $ProjectPath -c Debug -o "$OutputDir\app"
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

Write-Host "Creating $ZipName..." -ForegroundColor Cyan
Compress-Archive -Path "$OutputDir\app\*" -DestinationPath "$OutputDir\$ZipName"

$exe = Get-Item "$OutputDir\app\SyslogCEFAnalyzer.exe"
$zip = Get-Item "$OutputDir\$ZipName"
Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "  EXE: $($exe.FullName) ($([math]::Round($exe.Length / 1KB)) KB)"
Write-Host "  ZIP: $($zip.FullName) ($([math]::Round($zip.Length / 1KB)) KB)"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Go to https://github.com/el-bakkali/SyslogCEFAnalyzer/releases/new"
Write-Host "  2. Choose tag: v$Version"
Write-Host "  3. Title: Syslog CEF Analyzer v$Version"
Write-Host "  4. Attach: $OutputDir\$ZipName"
Write-Host "  5. Publish release"
