using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace OfficePcAudit
{
    public sealed class Check
    {
        public int Id; public string Area,Name,Criteria,Advice,Method; public Func<Finding> Read;
    }
    internal sealed class QueryStillRunningException : TimeoutException { }
    public sealed class AuditEngine
    {
        internal static Finding MicrosoftLoginFinding()
        {
            return R(Verdict.Partial,"Windows 로그인: Microsoft 계정 확인 (부분통과). 확인된 범위는 계정 유형뿐이며 보안 설정은 미검증입니다. 2단계 인증 또는 패스키 등 인증 수단, 복구 정보, 최근 로그인 활동을 직접 확인하십시오. 충분하면 검토 의견에 확인일과 결과를 기록하고, 미흡하면 보완하고, 미확인이면 검토를 유지하십시오. 자동 판정은 부분통과로 유지합니다. 로컬 최소 암호 길이 정책은 적용하지 않습니다. Office·OneDrive 계정은 판정에 사용하지 않았습니다.");
        }
        const string Cv=@"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        const string SystemPolicy=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        private readonly Lazy<Dictionary<string,object>> defender = new Lazy<Dictionary<string,object>>(()=>LocalSystem.One(LocalSystem.Defender,
            "SELECT AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,AMRunningMode FROM MSFT_MpComputerStatus"));
        private readonly Lazy<List<Dictionary<string,object>>> products = new Lazy<List<Dictionary<string,object>>>(()=>LocalSystem.Query(LocalSystem.Security,"SELECT displayName FROM AntiVirusProduct"));
        static readonly object queryLock=new object();
        static Task pendingQuery;
        internal static T Timed<T>(Func<T> read,Func<bool> cancelled,int timeoutMs)
        {
            if(cancelled())throw new OperationCanceledException();
            Task<T> task;
            lock(queryLock)
            {
                // Native calls cannot always be cancelled. Never accumulate abandoned queries on retry.
                if(pendingQuery!=null&&!pendingQuery.IsCompleted)throw new QueryStillRunningException();
                task=Task.Factory.StartNew(read,CancellationToken.None,TaskCreationOptions.DenyChildAttach,TaskScheduler.Default);
                pendingQuery=task;
                task.ContinueWith(t=>{var observed=t.Exception;},TaskContinuationOptions.OnlyOnFaulted);
            }
            var watch=System.Diagnostics.Stopwatch.StartNew();
            while(true)
            {
                if(cancelled())throw new OperationCanceledException();
                try { if(task.Wait(Math.Min(100,Math.Max(1,timeoutMs-(int)watch.ElapsedMilliseconds))))return task.GetAwaiter().GetResult(); }
                catch(AggregateException) { return task.GetAwaiter().GetResult(); }
                if(watch.ElapsedMilliseconds>=timeoutMs)throw new TimeoutException();
            }
        }
        internal static string ScanHistory(System.Collections.Generic.Dictionary<string,object> row,DateTime now)
        {
            Func<string,string> show=key=>{
                object value;if(!row.TryGetValue(key,out value)||value==null)return "완료 기록 없음";
                var date=LocalSystem.Date(value);
                if(!date.HasValue||date.Value.Year<2000)return "완료 기록 없음 / 날짜 확인 필요";
                if(date.Value>now.AddMinutes(5))return "시각 이상 / 확인 필요";
                return Labels.Time(date.Value);
            };
            return "빠른 검사 최근 완료="+show("QuickScanEndTime")+" / 전체 검사 최근 완료="+show("FullScanEndTime")+". 완료 기록만 조회하며 새 검사를 실행하지 않습니다. 최근성 판정·감염 없음 보장은 하지 않습니다.";
        }
        static Finding R(Verdict status,string value) { return new Finding { Status=status,Value=value }; }
        static string On(bool b) { return b?"켜짐":"꺼짐"; }
        static string Nv(int? v) { return v.HasValue?v.Value.ToString(CultureInfo.InvariantCulture):"미설정/값 없음"; }
        static string Edition() { return LocalSystem.RegText(true,Cv,"EditionID"); }
        static string Drive() { string d=Environment.GetEnvironmentVariable("SystemDrive");if(String.IsNullOrEmpty(d) || d.Length!=2 || d[1]!=':')throw new InvalidOperationException("시스템 드라이브를 확인하지 못했습니다.");return d; }
        public static Dictionary<string,string> ReadInfo(Action<string> progress)
        { return ReadInfo(progress,()=>false); }
        public static Dictionary<string,string> ReadInfo(Action<string> progress,Func<bool> cancelled)
        {
            var info=new Dictionary<string,string>();
            Action<string,Func<string>> add=(name,read)=> {
                if(cancelled())throw new OperationCanceledException();
                progress(name);
                try { info[name]=Timed(read,cancelled,15000); }
                catch(OperationCanceledException){throw;}
                catch(Exception e){info[name]="확인 불가: "+LocalSystem.Error(e);}
            };
            add("PC 이름",()=>Environment.MachineName);
            add("제조사 / 모델",()=>{var x=LocalSystem.One(LocalSystem.Cim,"SELECT Manufacturer,Model FROM Win32_ComputerSystem");return LocalSystem.Text(x,"Manufacturer")+" / "+LocalSystem.Text(x,"Model");});
            add("CPU / 아키텍처",()=>{var x=LocalSystem.One(LocalSystem.Cim,"SELECT Name,Architecture FROM Win32_Processor");return LocalSystem.Text(x,"Name")+" / "+(LocalSystem.Number(x,"Architecture")==9?"AMD64 (Intel/AMD x64)":"지원 대상 아키텍처 아님");});
            add("RAM",()=>{var x=LocalSystem.One(LocalSystem.Cim,"SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");return (Convert.ToDouble(x["TotalPhysicalMemory"])/1073741824d).ToString("N1")+" GB";});
            add("Windows",()=>{var x=LocalSystem.One(LocalSystem.Cim,"SELECT Caption,Version,BuildNumber FROM Win32_OperatingSystem");return LocalSystem.Text(x,"Caption")+" / "+Edition()+" / "+LocalSystem.RegText(true,Cv,"DisplayVersion")+" / 빌드 "+LocalSystem.Text(x,"BuildNumber")+"."+Nv(LocalSystem.RegInt(true,Cv,"UBR"));});
            add("Windows 설치일",()=>{var x=LocalSystem.One(LocalSystem.Cim,"SELECT InstallDate FROM Win32_OperatingSystem");var d=LocalSystem.Date(x["InstallDate"]);return d.HasValue?d.Value.ToString("yyyy-MM-dd HH:mm"):"확인 불가";});
            add("시스템 드라이브",()=>LocalSystem.Disk(Drive()));
            add("펌웨어",()=>LocalSystem.Firmware());
            add("Windows 로그인 계정",()=>Environment.UserName+" (직접 입력한 PC 사용자와 별개)");
            return info;
        }
        public List<Check> Checks()
        {
            var list=new List<Check>();
            Action<string,string,string,string,string,Func<Finding>> add=(area,name,criteria,advice,method,read)=>list.Add(new Check {Id=list.Count+1,Area=area,Name=name,Criteria=criteria,Advice=advice,Method=method,Read=read});
            add("운영체제","Windows 지원 상태","Home/Pro 내장 수명 주기표. Windows 10은 조직 운영기준상 조치 필요.","지원 중인 Windows 버전으로 전환을 검토하십시오. ESU 예외는 담당자가 별도 검토하십시오.","HKLM CurrentVersion: EditionID, DisplayVersion, CurrentBuildNumber",()=>{
                int build; if(!Int32.TryParse(LocalSystem.RegText(true,Cv,"CurrentBuildNumber"),out build))throw new InvalidOperationException("OS 빌드를 읽지 못했습니다.");
                string why;var status=Rules.Os(Edition(),build,LocalSystem.RegText(true,Cv,"DisplayVersion"),DateTime.Now,out why);return R(status,Edition()+" / "+build+" / "+why);});
            add("운영체제","최근 보안·누적 업데이트 기록","로컬 QFE에서 분류 가능한 최근 업데이트 설치 후 45일 이내. 최신성 보장 아님.","Windows Update 화면에서 설치 기록과 미설치 업데이트를 직접 확인하십시오. 점검 도구는 업데이트 검색·설치를 하지 않습니다.","로컬 WMI Win32_QuickFixEngineering: HotFixID, Description, InstalledOn",()=>{
                var rows=LocalSystem.Query(LocalSystem.Cim,"SELECT HotFixID,Description,InstalledOn FROM Win32_QuickFixEngineering");
                var eligible=rows.Where(x=>{string s=LocalSystem.Text(x,"Description");return s.IndexOf("Security",StringComparison.OrdinalIgnoreCase)>=0 || s.Contains("보안") || s.IndexOf("Cumulative",StringComparison.OrdinalIgnoreCase)>=0 || s.Contains("누적");}).ToList();
                var dated=eligible.Where(x=>LocalSystem.Date(x["InstalledOn"]).HasValue).OrderByDescending(x=>LocalSystem.Date(x["InstalledOn"])).ToList();
                if(dated.Count==0)return R(Verdict.Review,"분류 가능한 보안·누적 업데이트 날짜가 없습니다. QFE는 전체 업데이트 이력이 아닙니다.");
                var recent=dated[0];var d=LocalSystem.Date(recent["InstalledOn"]);var v=Rules.Age(d,DateTime.Now,45,45);
                if(v==Verdict.Good && eligible.Any(x=>!LocalSystem.Date(x["InstalledOn"]).HasValue))v=Verdict.Review;
                return R(v,LocalSystem.Text(recent,"HotFixID")+" / "+LocalSystem.Text(recent,"Description")+" / "+d.Value.ToString("yyyy-MM-dd")+" / 로컬 기록만 조회. 서버 비교 안 함.");});
            add("운영체제","자동 업데이트 설정","자동 업데이트 설정 활성 통과, 명시적 비활성 조치 필요. 실제 설치 최신성은 별도 항목.",
                "Windows Update에서 자동 업데이트 설정을 확인하십시오. 이 점검은 검색·다운로드·설치를 실행하지 않습니다.",
                "NoAutoUpdate 정책; Microsoft.Update.AutoUpdate.Settings.NotificationLevel (읽기 전용)",()=>{
                int? no=LocalSystem.RegInt(true,@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU","NoAutoUpdate");
                if(no==1)return R(Verdict.Weak,"자동 업데이트 OFF / NoAutoUpdate=1 (정책)");
                Type t=Type.GetTypeFromProgID("Microsoft.Update.AutoUpdate",true);object obj=Activator.CreateInstance(t);
                try { dynamic au=obj;object settings=au.Settings;try {
                    dynamic cfg=settings;int level=(int)cfg.NotificationLevel;
                    return R(Rules.AutoUpdate(no,level),"자동 업데이트="+(level>=2&&level<=4?"ON":level==1?"OFF":"판별 불가")+" / NoAutoUpdate="+Nv(no)+" / NotificationLevel="+level+" (0=미구성, 1=비활성, 2=다운로드 전 알림, 3=설치 전 알림, 4=예약 설치). 업데이트 일시중지·실제 설치 최신성은 이 판정 범위 밖입니다.");
                } finally {Marshal.FinalReleaseComObject(settings);} } finally {Marshal.FinalReleaseComObject(obj);}
            });
            add("악성코드 방어","Defender 실행·실시간 보호","Defender 서비스·백신·실시간 보호 활성. 타사 보호 사용 여부와 구분.","Windows 보안에서 활성 백신과 실시간 보호를 확인하십시오. 타사 백신을 먼저 삭제하지 마십시오.","로컬 WMI MSFT_MpComputerStatus (서비스·실시간 보호, QuickScanEndTime, FullScanEndTime); WscGetSecurityProviderHealth(ANTIVIRUS)",()=>{
                var x=defender.Value; bool service=LocalSystem.Bool(x,"AMServiceEnabled"), av=LocalSystem.Bool(x,"AntivirusEnabled"),rt=LocalSystem.Bool(x,"RealTimeProtectionEnabled");
                string history;try {history=ScanHistory(LocalSystem.One(LocalSystem.Defender,"SELECT QuickScanEndTime,FullScanEndTime FROM MSFT_MpComputerStatus"),DateTime.Now);}catch(Exception e){history="최근 검사 이력 확인 불가: "+LocalSystem.Error(e);}
                string value="Defender 서비스="+On(service)+", 백신="+On(av)+", 실시간 보호="+On(rt)+", 모드="+LocalSystem.Text(x,"AMRunningMode")+" / "+history;
                if(service&&av&&rt)return R(Verdict.Good,value);
                int health;int hr=LocalSystem.WscGetSecurityProviderHealth(4,out health);
                if(hr!=0)return R(Verdict.Unknown,value+" / 전체 백신 상태 조회 실패: HRESULT="+hr+". 보호 공백 여부 미확인.");
                return R(health==0?Verdict.Review:Verdict.Weak,value+" / Windows 보안 센터 집계="+health+" (0=통과, 1=미감시, 2=불량, 3=일시중지). Defender 외 보호 가능성은 별도 확인.");});
            add("악성코드 방어","Defender 정의 업데이트 시각","3일 이내 통과, 3일 초과~7일 수동 확인 필요, 7일 초과 조치 필요. 비활성 Defender는 별도 확인.","활성 백신의 정의 업데이트를 확인하십시오. 이 프로그램은 업데이트나 검사를 실행하지 않습니다.","로컬 WMI MSFT_MpComputerStatus.AntivirusSignatureLastUpdated",()=>{
                var x=defender.Value; if(!LocalSystem.Bool(x,"AntivirusEnabled"))return R(Verdict.Review,"Defender가 활성 백신이 아닙니다. 정의 시각을 활성 백신의 상태로 해석하지 않습니다.");
                var d=LocalSystem.Date(x["AntivirusSignatureLastUpdated"]);return R(Rules.Age(d,DateTime.Now,3,7),d.HasValue?Labels.Time(d.Value):"정의 업데이트 시각 기록 없음. 활성 백신에서 수동 확인 필요");});
            add("악성코드 방어","타사 백신 사용 승인·라이선스","타사 제품 등록 시 사용 승인·업무용 라이선스 수동 확인 필요. 설치만으로 유료·무단 사용을 단정하지 않음.","제품명과 업무용 이용조건을 담당자가 확인하십시오. 승인된 제품은 검토 의견에 사유를 남기십시오.","로컬 WMI root SecurityCenter2 AntiVirusProduct.displayName (파일 경로·프로세스 실행 없음)",()=>{
                var names=products.Value.Select(x=>LocalSystem.Text(x,"displayName")).ToList();
                var others=names.Where(x=>!String.Equals(x,"Windows Defender",StringComparison.OrdinalIgnoreCase)&&!String.Equals(x,"Microsoft Defender Antivirus",StringComparison.OrdinalIgnoreCase)&&!String.Equals(x,"Microsoft Defender",StringComparison.OrdinalIgnoreCase)).ToList();
                return R(others.Count>0?Verdict.Review:Verdict.Good,"등록 제품: "+(names.Count==0?"없음":String.Join(", ",names))+". 등록 정보는 잔여 항목일 수 있으며 설치·구독 상태를 보장하지 않습니다.");});
            add("네트워크 보안","Windows 방화벽 프로필","도메인·개인·공용 세 프로필 모두 활성화.","Windows 보안에서 꺼진 프로필과 업무상 예외를 검토하십시오.","로컬 COM HNetCfg.FwPolicy2: FirewallEnabled, CurrentProfileTypes (조회 전용)",()=>{
                Type t=Type.GetTypeFromProgID("HNetCfg.FwPolicy2",true);object obj=Activator.CreateInstance(t);
                try {dynamic fw=obj;int current=(int)fw.CurrentProfileTypes;bool d=fw.FirewallEnabled[1],p=fw.FirewallEnabled[2],u=fw.FirewallEnabled[4];return R(d&&p&&u?Verdict.Good:Verdict.Weak,"도메인="+On(d)+", 개인="+On(p)+", 공용="+On(u)+" / 현재 프로필 비트="+current+" (1=도메인, 2=개인, 4=공용)");}
                finally {Marshal.FinalReleaseComObject(obj);} });
            add("네트워크 보안","원격 데스크톱","기본 비활성 권장. 활성화는 업무 필요성 확인. 타사 원격 도구는 조사하지 않음.","필요한 원격접속만 승인하고 계정·접근 범위를 확인하십시오.","HKLM SYSTEM CurrentControlSet Control Terminal Server.fDenyTSConnections; EditionID",()=>{
                if(Edition().StartsWith("Core",StringComparison.Ordinal))return R(Verdict.Good,"Windows Home은 기본 원격 데스크톱 호스트 미지원. 타사 원격 도구 존재 여부는 검사하지 않았습니다.");
                int? n=LocalSystem.RegInt(true,@"SYSTEM\CurrentControlSet\Control\Terminal Server","fDenyTSConnections");return R(n==1?Verdict.Good:Verdict.Review,"fDenyTSConnections="+Nv(n));});
            add("네트워크 보안","SMBv1 선택 기능","SMB1Protocol 비활성 또는 제거 상태.","구형 장비 의존성을 확인한 후 담당자가 SMBv1 비활성화를 검토하십시오.","로컬 WMI Win32_OptionalFeature(Name=SMB1Protocol).InstallState",()=>{
                var x=LocalSystem.Query(LocalSystem.Cim,"SELECT Name,InstallState FROM Win32_OptionalFeature WHERE Name='SMB1Protocol'");if(x.Count==0)return R(Verdict.Review,"선택 기능 조회는 성공했으나 항목이 없습니다. 지원 여부는 수동 확인하십시오.");
                int n=LocalSystem.Number(x[0],"InstallState");return R(n==1?Verdict.Weak:n==2?Verdict.Good:n==3?Verdict.Good:Verdict.Review,"InstallState="+n+" (1=활성, 2=비활성, 3=제거, 4=알 수 없음). 개별 클라이언트·서버 상태는 별도 확인.");});
            add("네트워크 보안","공유폴더 존재","일반 디스크 공유가 있으면 업무 필요성 확인. 기본 관리 공유는 구분.","공유 목적·접근 권한·개인정보 포함 여부를 확인하십시오. 이 도구는 공유 내용을 열거나 삭제하지 않습니다.","로컬 WMI Win32_Share.Name, Type (공유 경로·폴더 내용 미수집)",()=>{
                var shares=LocalSystem.Query(LocalSystem.Cim,"SELECT Name,Type FROM Win32_Share");
                var normal=new List<string>();var admin=new List<string>();
                foreach(var x in shares){uint type=Convert.ToUInt32(x["Type"]);string name=LocalSystem.Text(x,"Name");if((type&0x80000000)!=0)admin.Add(name);else if(type==0)normal.Add(name);}
                return R(normal.Count>0?Verdict.Review:Verdict.Good,"일반 디스크 공유: "+(normal.Count==0?"없음":String.Join(", ",normal))+" / 기본·관리 공유: "+(admin.Count==0?"없음":String.Join(", ",admin))+". 필요성·권한은 미검증.");});
            add("계정 보안","Guest 계정","내장 Guest(SID 끝 -501) 비활성화.","업무상 필요한지 확인하고 Guest 계정을 사용하지 않는 구성을 검토하십시오.","로컬 WMI Win32_UserAccount(LocalAccount=TRUE): Name, SID, Disabled",()=>{
                var users=LocalSystem.Query(LocalSystem.Cim,"SELECT Name,SID,Disabled FROM Win32_UserAccount WHERE LocalAccount=TRUE");var x=users.FirstOrDefault(u=>LocalSystem.Text(u,"SID").EndsWith("-501",StringComparison.Ordinal));
                if(x==null)return R(Verdict.Review,"계정 조회는 성공했으나 내장 Guest 항목이 없습니다. 수동 확인하십시오.");bool disabled=LocalSystem.Bool(x,"Disabled");return R(disabled?Verdict.Good:Verdict.Weak,LocalSystem.Text(x,"Name")+" / "+(disabled?"비활성":"활성"));});
            add("계정 보안","로그인 계정·암호 정책","Windows 로그인 MS 계정 확인은 부분통과이며 계정 보안 수동 검토가 필요합니다. 로컬 계정은 최소 암호 길이 정책 12자 이상 통과, 미달 조치 필요.","MS 계정은 2단계 인증 또는 패스키 등 인증 수단, 복구 정보, 최근 로그인 활동을 확인해 검토 의견에 기록하십시오. 미흡하면 보완하고 미확인이면 검토를 유지하십시오. 로컬은 최소 암호 길이 12자 이상을 검토하십시오. 암호·복구 코드·인증 코드를 이 도구에 입력하지 마십시오.","현재 세션 WTS 사용자 + NetUserGetInfo(NULL, 24); 로컬은 NetUserModalsGet(NULL, 0)",()=>{
                var kind=LocalSystem.WindowsLoginKind();
                if(kind==LocalSystem.LoginKind.Microsoft)return MicrosoftLoginFinding();
                if(kind==LocalSystem.LoginKind.Other)return R(Verdict.Review,"Windows 로그인이 도메인·Entra·기타 공급자이거나 이 기준의 대상 계정이 아닙니다. MS 계정·로컬 계정으로 임의 판정하지 않습니다.");
                var p=LocalSystem.Policy<LocalSystem.PasswordPolicy>(0);return R(Rules.Password(p.MinLength),"Windows 로그인: 로컬 계정 / 최소 길이="+p.MinLength+"자 / 기록="+p.History+"개 / 최대 사용기간="+(p.MaxAge==UInt32.MaxValue?"만료 없음":(p.MaxAge/86400)+"일")+". 실제 암호·Windows Hello·Microsoft 계정 정책은 검사하지 않았습니다.");});
            add("계정 보안","로컬 계정 잠금 정책","실패 1~10회, 잠금 15분 이상 또는 관리자 해제이면 통과. 미달 조치 필요. 로컬 계정 정책 범위.","로컬 계정 정책을 검토하십시오. Windows Hello·Microsoft 계정 잠금은 이 값으로 판정하지 않습니다.","NetUserModalsGet(NULL, level 3)",()=>{
                var p=LocalSystem.Policy<LocalSystem.LockoutPolicy>(3);return R(Rules.Lockout(p.Threshold,p.Duration),"실패 허용="+p.Threshold+"회 (0=잠금 없음) / 잠금="+(p.Duration==UInt32.MaxValue?"관리자 해제":p.Duration/60+"분")+" / 실패 집계 초기화="+p.Window/60+"분. 로컬 SAM 정책만 확인.");});
            add("계정 보안","자동 로그인 설정","일반 Winlogon 자동 로그인 미설정 또는 비활성은 통과. 다른 로그인 경로는 별도 확인.","공유·분실 위험을 고려해 자동 로그인 필요성을 검토하십시오.","HKLM SOFTWARE Microsoft Windows NT CurrentVersion Winlogon.AutoAdminLogon만 조회",()=>{
                string s=LocalSystem.RegText(true,Cv+@"\Winlogon","AutoAdminLogon");return R(Rules.AutoLogon(s),"AutoAdminLogon="+(String.IsNullOrEmpty(s)?"값 없음":s)+". 값 없음은 일반 자동 로그인 미설정이나 다른 로그인 우회 경로까지 증명하지 않습니다. 암호 저장값은 읽지 않았습니다.");});
            add("데이터 보안","시스템 드라이브 암호화","보호 켜짐 및 암호화 완료 통과. 보호 꺼짐·변환 미완료 조치 필요. 공급자 미상 상태는 수동 확인.",
                "미암호화·보호 중지·진행 상태에 맞춰 담당자가 암호화를 검토하십시오. 복구키 보관은 별도 확인하며 키를 수집하지 않습니다.",
                "Win32_EncryptableVolume.GetProtectionStatus / GetConversionStatus (상태 조회만)",()=>{
                var x=LocalSystem.EncryptionStatus(Drive());if(x==null)return R(Verdict.Review,"조회는 성공했으나 시스템 드라이브 항목이 없습니다. 기능 지원·관리 상태 수동 확인 필요.");
                int p=LocalSystem.Number(x,"ProtectionStatus"),c=LocalSystem.Number(x,"ConversionStatus"),percent=LocalSystem.Number(x,"EncryptionPercentage");
                if(p<0||p>2||c<0||c>5||percent<0||percent>100)throw new InvalidOperationException("암호화 공급자가 유효하지 않은 상태값을 반환했습니다.");
                string[] names={"암호화 해제 상태","암호화 완료","암호화 진행 중","암호 해제 진행 중","암호화 진행 일시중지","암호 해제 진행 일시중지"};
                return R(Rules.Encryption(p,c),"보호="+(p==1?"켜짐":p==0?"꺼짐":"공급자 미상")+" / 변환="+names[c]+" / 암호화율="+percent+"%"+
                    (p==0&&c==1?" / 암호화는 완료됐으나 키 보호가 꺼져 있습니다. 보호 일시중지 가능.":"")+" / 복구키 보관 여부는 별도 수동 확인.");
            });
            add("물리적 보안","화면 자동 잠금","10분 이내 비활동 잠금 또는 인증 화면보호기 조건 충족 시 통과. 두 경로 모두 미달이면 조치 필요. 화면 꺼짐은 잠금으로 인정하지 않음.","자동 잠금과 복귀 시 인증을 설정하고 자리를 비울 때 Win+L을 사용하십시오. 실제 잠금은 수동 시험하십시오.","HKLM Policies System.InactivityTimeoutSecs; HKCU 화면보호기 정책 + SystemParametersInfo GET 현재 화면보호기 상태",ReadScreenLock);
            add("계정 보안","사용자 계정 컨트롤(UAC)","EnableLUA=1, 관리자 승인 프롬프트 활성, 보안 데스크톱 사용.","UAC를 켜고 관리자 작업 시 승인 화면이 표시되는지 확인하십시오.","HKLM Policies System: EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop",()=>{
                int? lua=LocalSystem.RegInt(true,SystemPolicy,"EnableLUA"),consent=LocalSystem.RegInt(true,SystemPolicy,"ConsentPromptBehaviorAdmin"),secure=LocalSystem.RegInt(true,SystemPolicy,"PromptOnSecureDesktop");
                Verdict v=lua==0||consent==0?Verdict.Weak:lua==1&&consent>=1&&consent<=5&&secure==1?Verdict.Good:Verdict.Review;
                return R(v,"EnableLUA="+Nv(lua)+" / ConsentPromptBehaviorAdmin="+Nv(consent)+" / PromptOnSecureDesktop="+Nv(secure));});
            add("부팅 보안","Secure Boot","UEFI Secure Boot 활성 권장. 부재는 수동 확인 필요.","장비 지원·부팅 구성을 확인한 후 담당자가 검토하십시오. BIOS 설정을 자동 변경하지 않습니다.","GetFirmwareType; HKLM SYSTEM CurrentControlSet Control SecureBoot State.UEFISecureBootEnabled",()=>{
                string firmware=LocalSystem.Firmware();int? n=LocalSystem.RegInt(true,@"SYSTEM\CurrentControlSet\Control\SecureBoot\State","UEFISecureBootEnabled");return R(firmware=="UEFI"&&n==1?Verdict.Good:n==0||firmware=="BIOS"?Verdict.Weak:Verdict.Review,"펌웨어="+firmware+" / Secure Boot="+Nv(n));});
            add("부팅 보안","TPM 상태","TPM 2.0 및 현재 준비 완료는 통과. 미존재·구버전·준비 미완료는 조치 필요.",
                "상태 코드와 장비 지원 여부를 담당자가 검토하십시오. TPM 초기화·삭제는 자동 실행하지 않습니다.",
                "Win32_Tpm.SpecVersion; IsReadyInformation(IsReady, Information) 상태 조회",()=>{
                var x=LocalSystem.TpmStatus();if(x==null)return R(Verdict.Weak,"TPM 조회 성공, 노출된 TPM 장치 없음. 펌웨어 비활성 또는 미지원 가능. 담당자가 지원 여부를 확인하십시오.");
                bool ready=LocalSystem.Bool(x,"IsReady");string spec=LocalSystem.Text(x,"SpecVersion");

                return R(Rules.Tpm(spec,ready),"규격="+spec+" / 현재 준비 완료="+(ready?"예":"아니오")+" / 준비 정보 비트=0x"+Convert.ToUInt32(x["Information"]).ToString("X8")+". 초기 활성값만으로 판정하지 않습니다.");
            });
            return list;
        }
        private static Finding ReadScreenLock()
        {
            int? inactivity=LocalSystem.RegInt(true,SystemPolicy,"InactivityTimeoutSecs");
            string policy=@"Software\Policies\Microsoft\Windows\Control Panel\Desktop", user=@"Control Panel\Desktop";
            int? pa=LocalSystem.RegInt(false,policy,"ScreenSaveActive"),pt=LocalSystem.RegInt(false,policy,"ScreenSaveTimeOut"),ps=LocalSystem.RegInt(false,policy,"ScreenSaverIsSecure");
            int? active=pa??LocalSystem.ScreenSetting(16),timeout=pt??LocalSystem.ScreenSetting(14),secure=ps??LocalSystem.ScreenSetting(0x76);
            string file=LocalSystem.RegText(false,policy,"SCRNSAVE.EXE");if(String.IsNullOrEmpty(file))file=LocalSystem.RegText(false,user,"SCRNSAVE.EXE");
            bool machineGood=inactivity>0&&inactivity<=600;
            bool saverGood=active==1&&secure==1&&timeout>0&&timeout<=600&&!String.IsNullOrEmpty(file);
            Verdict status=Rules.ScreenLock(machineGood,saverGood);
            return R(status,"컴퓨터 잠금="+Nv(inactivity)+"초 / 화면보호기 활성="+Nv(active)+", 대기="+Nv(timeout)+"초, 복귀 인증="+Nv(secure)+", 실행 항목="+(!String.IsNullOrEmpty(file)?"지정됨":"없음")+" / 사용자 정책 값 우선, 없으면 현재 실행 계정의 Windows API 유효값 조회. 화면보호기 복귀 인증이 꺼져 있으면 이 경로는 기준 미달. 다른 계정으로 상승했다면 실제 PC 사용자 설정은 별도 확인. 절전 후 잠금 등 다른 경로와 실제 동작은 미검증.");
        }
        public Audit Run(Dictionary<string,string> info,Action<int,string> progress,Func<bool> cancelled)
        {
            var audit=new Audit();foreach(var x in info)audit.Info.Add(x.Key,x.Value);
            var checks=Checks();
            foreach(var c in checks)
            {
                if(cancelled()) return audit;
                progress((c.Id-1)*100/checks.Count,c.Name);Finding f;
                try { f=Timed(c.Read,cancelled,15000); } catch(OperationCanceledException) { return audit; } catch(Exception e) { f=R(Verdict.Unknown,LocalSystem.Error(e)); }
                f.Id=c.Id;f.Area=c.Area;f.Name=c.Name;f.Criteria=c.Criteria;f.Advice=c.Advice;f.Method=c.Method;f.Time=DateTime.Now;audit.Findings.Add(f);
            }
            if(cancelled())return audit;
            audit.Finished=DateTime.Now;progress(100,"점검 완료");return audit;
        }
    }
}







