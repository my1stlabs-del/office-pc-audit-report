$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$files = Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.cs'
$code = ($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
$forbidden = @('HttpClient','WebClient','WebRequest','TcpClient','UdpClient','Dns.','System.Net.Sockets','Process.Start','SetValue(','CreateSubKey(','DeleteSubKey','DeleteValue(','ManagementObject.Put','File.Delete','File.Move','WriteAllText','WriteAllBytes','SaveFileDialog','powershell.exe','cmd.exe')
foreach ($token in $forbidden) {
    if ($code.Contains($token)) { throw "제품 소스에서 금지 토큰 발견: $token" }
}
if (-not $code.Contains('OpenSubKey(path,false)')) { throw '레지스트리 읽기 전용 모드 확인 실패' }
if (-not $code.Contains('NetUserModalsGet(null,level')) { throw '로컬 계정 정책 조회 경계 확인 실패' }
if (-not $code.Contains('NetLocalGroupGetMembers(null,name.ToString(),0')) { throw '로컬 관리자 SID 조회 경계 확인 실패' }
$store = Get-Content -LiteralPath (Join-Path $root 'src\ReportStore.cs') -Raw
if (-not $store.Contains('FileMode.CreateNew') -or -not $store.Contains('0x02200000')) { throw '저장 제한 확인 실패' }
foreach ($file in $files | Where-Object { $_.Name -ne 'ReportStore.cs' }) {
    $text = Get-Content -LiteralPath $file.FullName -Raw
    foreach ($token in @('new FileStream','new StreamWriter','Directory.CreateDirectory','File.Create')) {
        if ($text.Contains($token)) { throw "저장 경계 외 파일 쓰기 발견: $($file.Name) / $token" }
    }
}
$local = Get-Content -LiteralPath (Join-Path $root 'src\LocalSystem.cs') -Raw
if (($local | Select-String -Pattern '\.InvokeMethod\(' -AllMatches).Matches.Count -ne 1 -or -not $local.Contains('if(!AllowedStatusMethod(space,method))')) { throw 'WMI 상태 메서드 허용 경계 확인 실패' }
[xml]$manifest = Get-Content -LiteralPath (Join-Path $root 'src\app.manifest') -Raw
$level = $manifest.SelectSingleNode("//*[local-name()='requestedExecutionLevel']").GetAttribute('level')
if ($level -ne 'asInvoker') { throw '권한 상승 매니페스트 발견' }
Write-Output 'PASS: source guard checks (heuristic, not a complete security proof)'

