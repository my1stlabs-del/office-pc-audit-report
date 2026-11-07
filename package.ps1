$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$version = '1.0.0'
& (Join-Path $root 'build.ps1') -Test
& (Join-Path $root 'tests/review-source.ps1')
$testExe = Join-Path $root 'tests/bin/AuditTests.exe'
$example = & $testExe --example
if ($LASTEXITCODE -ne 0) { throw '가상 보고서 생성 실패' }
$example | Set-Content -LiteralPath (Join-Path $root 'docs/보고서_예시.html') -Encoding UTF8
$guides = & $testExe --guides
if ($LASTEXITCODE -ne 0) { throw '조치 안내 생성 실패' }
$guides | Set-Content -LiteralPath (Join-Path $root 'docs/조치방법.txt') -Encoding UTF8
& (Join-Path $root 'tests/review-repository.ps1')
$destination = Join-Path $root "배포버전/$version"
$zip = Join-Path $root "배포버전/업무용_PC_보안점검_${version}_win-x64.zip"
if ((Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath $zip)) {
    throw '배포본이 이미 있습니다. 기존 배포본을 old에 보관한 뒤 다시 실행하십시오.'
}
New-Item -ItemType Directory -Path $destination | Out-Null
foreach ($name in @('OfficePcAudit.exe','OfficePcAudit.exe.config','사용설명서.txt')) {
    Copy-Item -LiteralPath (Join-Path $root "dist/$name") -Destination $destination
}
$docs = Join-Path $destination '설명자료'
New-Item -ItemType Directory -Path $docs | Out-Null
foreach ($name in @('점검기준.md','조치방법.txt','조치안내_근거.md','보고서_예시.html','검증결과.md','구성요소와라이선스.md')) {
    Copy-Item -LiteralPath (Join-Path $root "docs/$name") -Destination $docs
}
Compress-Archive -LiteralPath $destination -DestinationPath $zip
Get-FileHash -LiteralPath $zip -Algorithm SHA256 | Format-List
Write-Output "배포 완료: $destination"
