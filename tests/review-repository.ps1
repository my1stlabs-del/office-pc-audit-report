$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $candidates = @(git -c core.quotepath=false ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw 'Git 파일 목록 조회 실패' }
    foreach ($path in $candidates) {
        if ($path -match '(^|/)(old|dist|release|배포버전|결과출력|\.review|bin)/|\.(exe|dll|zip|pdb|log)$|(^|/)PC보안점검_') {
            throw "공개 대상에 로컬 산출물 포함: $path"
        }
        $allowed = $path -match '^(src/[^/]+\.(cs|config|manifest)|tests/[^/]+\.(cs|ps1)|docs/[^/]+\.(md|txt)|docs/보고서_예시\.html|README\.md|build\.ps1|package\.ps1|\.gitignore)$'
        if (-not $allowed) { throw "공개 허용 목록 밖의 파일입니다. 직접 검토하십시오: $path" }
        $text = Get-Content -LiteralPath $path -Raw
        if ($text -match '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|C:\\Users\\') {
            throw "개인 경로·비밀값 의심: $path"
        }
    }
    $example = Get-Content -LiteralPath 'docs/보고서_예시.html' -Raw
    if ($example -notmatch '가상 데이터' -or $example -notmatch '실제 PC 점검 결과가 아닙니다') { throw '가상 예시 표시 누락' }
    Write-Output "PASS: repository allowlist and heuristic privacy checks ($($candidates.Count) files; not a complete secret scan)"
} finally { Pop-Location }
