param([switch]$Test)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Windows x64 .NET Framework C# 컴파일러를 찾을 수 없습니다.' }
$output = Join-Path $root 'dist'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$sources = @(Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.cs' | ForEach-Object { $_.FullName })
$references = @('/r:System.dll','/r:System.Core.dll','/r:System.Management.dll','/r:System.Drawing.dll','/r:System.Windows.Forms.dll','/r:Microsoft.CSharp.dll')
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 "/win32manifest:$root\src\app.manifest" "/out:$output\OfficePcAudit.exe" $references $sources
if ($LASTEXITCODE -ne 0) { throw '프로그램 빌드 실패' }
Copy-Item -LiteralPath (Join-Path $root 'docs\사용설명서.txt') -Destination $output
Copy-Item -LiteralPath (Join-Path $root 'src\OfficePcAudit.exe.config') -Destination $output
if ($Test) {
    $testOutput = Join-Path $root 'tests\bin'
    New-Item -ItemType Directory -Path $testOutput -Force | Out-Null
    & $compiler /nologo /target:exe /platform:x64 /optimize+ /codepage:65001 /main:OfficePcAudit.Tests "/out:$testOutput\AuditTests.exe" $references $sources (Join-Path $root 'tests\Tests.cs')
    if ($LASTEXITCODE -ne 0) { throw '테스트 빌드 실패' }
    & (Join-Path $testOutput 'AuditTests.exe')
    if ($LASTEXITCODE -ne 0) { throw '테스트 실패' }
}
Write-Output "빌드 완료: $output\OfficePcAudit.exe"
