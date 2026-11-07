using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace OfficePcAudit
{
    internal static class Tests
    {
        static int passed;
        static void Assert(bool ok,string name) {if(!ok)throw new Exception("FAIL: "+name);Console.WriteLine("PASS: "+name);passed++;}
        static void Throws(Action action,string name) {bool failed=false;try{action();}catch{failed=true;}Assert(failed,name);}
        public static Audit Example()
        {
            var a=new Audit {Started=new DateTime(2026,11,6,10,0,0),Finished=new DateTime(2026,11,6,10,2,0),Institution="예시 사무실",Inspector="점검자 예시",PcUser="사용자 예시",Notes="실제 장비의 결과가 아닌 가상 예시입니다.\n수동 확인 필요 항목은 담당자가 검토합니다.",FollowUp="담당자: __________\n예정일: __________\n조치 내용: ____________________"};
            a.Info.Add("PC 이름","예시-PC");a.Info.Add("제조사 / 모델","예시 제조사 / 사무용 PC");a.Info.Add("CPU / 아키텍처","예시 CPU / AMD64");a.Info.Add("RAM","16.0 GB");a.Info.Add("Windows","Windows 11 Home 25H2 / 빌드 26200 (가상)");a.Info.Add("시스템 드라이브","C: 총 500 GB / 여유 200 GB (가상)");
            foreach(var c in new AuditEngine().Checks())a.Findings.Add(new Finding {Id=c.Id,Area=c.Area,Name=c.Name,Criteria=c.Criteria,Advice=c.Advice,Method=c.Method,Status=c.Id==12?Verdict.Partial:(Verdict)((c.Id-1)%4),Value="가상 확인값: 실제 PC에서 조회하지 않았습니다.",Time=a.Finished.Value});
            return a;
        }

        static T Field<T>(MainForm form,string name)
        { return (T)typeof(MainForm).GetField(name,System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic).GetValue(form); }
        static void Finish(MainForm form,object result,Exception error,bool cancelled)
        {typeof(MainForm).GetMethod("Completed",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic).Invoke(form,new object[]{null,new System.ComponentModel.RunWorkerCompletedEventArgs(result,error,cancelled)});}
        static void WorkflowTests()
        {
            Assert(AuditEngine.Timed(()=>42,()=>false,1000)==42,"timed query returns result");
            bool nativeError=false;try{AuditEngine.Timed<int>(()=>{throw new InvalidOperationException("test");},()=>false,1000);}catch(InvalidOperationException){nativeError=true;}
            Assert(nativeError,"query error unwrapped");
            using(var entered=new System.Threading.ManualResetEventSlim())
            using(var release=new System.Threading.ManualResetEventSlim())
            using(var ended=new System.Threading.ManualResetEventSlim())
            {
                bool timeout=false;
                try{AuditEngine.Timed(()=>{entered.Set();release.Wait();ended.Set();return 1;},()=>false,200);}catch(TimeoutException){timeout=true;}
                Assert(timeout&&entered.IsSet,"stalled query times out");
                int launched=0;bool blocked=false;
                try{AuditEngine.Timed(()=>{launched++;return 2;},()=>false,200);}catch(TimeoutException){blocked=true;}
                Assert(blocked&&launched==0,"retry does not accumulate native queries");
                release.Set();Assert(ended.Wait(2000),"timed out native query drains");
            }
            // Wait for task bookkeeping before the next independent scenario.
            System.Threading.Thread.Sleep(50);
            using(var release=new System.Threading.ManualResetEventSlim())
            using(var ended=new System.Threading.ManualResetEventSlim())
            {
                var watch=System.Diagnostics.Stopwatch.StartNew();bool cancelled=false;
                try{AuditEngine.Timed(()=>{release.Wait();ended.Set();return 1;},()=>watch.ElapsedMilliseconds>150,15000);}catch(OperationCanceledException){cancelled=true;}
                Assert(cancelled&&watch.ElapsedMilliseconds<2000,"cancel interrupts wait promptly");
                release.Set();Assert(ended.Wait(2000),"cancelled native query drains");
            }
            System.Threading.Thread.Sleep(50);
            int reads=0;bool stopped=false;
            try{AuditEngine.ReadInfo(x=>reads++,()=>true);}catch(OperationCanceledException){stopped=true;}
            Assert(stopped&&reads==0,"cancel before basic info avoids all reads");
            reads=0;stopped=false;
            try{AuditEngine.ReadInfo(x=>reads++,()=>reads>=1);}catch(OperationCanceledException){stopped=true;}
            Assert(stopped&&reads==1,"cancel during info prevents next query");
            var incomplete=new AuditEngine().Run(new System.Collections.Generic.Dictionary<string,string>(),(p,n)=>{},()=>true);
            Assert(!incomplete.Finished.HasValue&&incomplete.Findings.Count==0,"cancelled scan stays incomplete");
            using(var form=new MainForm())
            {
                form.CreateControl();Assert(form.CurrentStep==0,"wizard starts with guidance");
                Assert(Field<ComboBox>(form,"filter").Items.Contains("부분통과"),"partial verdict available in GUI filter");
                form.Navigate(1);form.Navigate(2);Assert(form.CurrentStep==1&&!Field<Button>(form,"next").Enabled,"incomplete scan cannot advance");
                typeof(MainForm).GetMethod("StartScan",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic).Invoke(form,null);
                form.RequestCancel();
                Assert(form.CurrentScanState==MainForm.ScanState.Cancelling&&!Field<Button>(form,"cancel").Enabled,"real worker cancellation disables repeated requests");
                var deadline=System.Diagnostics.Stopwatch.StartNew();
                while(form.CurrentScanState==MainForm.ScanState.Cancelling&&deadline.ElapsedMilliseconds<3000){Application.DoEvents();System.Threading.Thread.Sleep(10);}
                Assert(form.CurrentScanState==MainForm.ScanState.Cancelled&&Field<Button>(form,"start").Enabled,"real worker cancellation completes and permits retry");
                form.SetScanState(MainForm.ScanState.Scanning,"test");form.Navigate(0);
                Assert(form.CurrentStep==1&&!Field<Button>(form,"previous").Enabled,"running scan locks navigation");
                Finish(form,null,new InvalidOperationException("synthetic failure"),false);
                Assert(form.CurrentScanState==MainForm.ScanState.Failed&&Field<Button>(form,"start").Enabled&&!Field<Button>(form,"save").Enabled&&Field<Label>(form,"summary").Text.Contains("실패"),"failure restores retry and blocks export");
                Finish(form,null,null,true);
                Assert(form.CurrentScanState==MainForm.ScanState.Cancelled&&Field<Label>(form,"summary").Text.Contains("중단"),"cancel clears running summary");
                Finish(form,Example(),null,false);Assert(form.CurrentStep==1&&Field<Button>(form,"next").Enabled,"completion waits for explicit next");
                form.Navigate(2);var answers=Field<System.Collections.Generic.List<ComboBox>>(form,"answers");
                Assert(answers.All(x=>x.SelectedIndex==0),"manual responses start unanswered");answers[0].SelectedIndex=1;
                Field<TextBox>(form,"institution").Text="보존 테스트";Field<TextBox>(form,"notes").Text="의견 유지";
                form.Navigate(3);Assert(Field<Label>(form,"exportSummary").Text.Contains("미응답 7개"),"output summary counts unanswered separately from unknown");
                form.Navigate(2);form.Navigate(1);form.Navigate(2);form.Navigate(3);
                Assert(answers[0].SelectedIndex==1&&Field<TextBox>(form,"institution").Text=="보존 테스트"&&Field<TextBox>(form,"notes").Text=="의견 유지","back navigation preserves input and responses");
            }
        }
        [STAThread] static int Main(string[] args)
        {
            Console.OutputEncoding=Encoding.UTF8;
            try
            {
                if(args.Length>0&&args[0]=="--guides") {
                    Console.WriteLine("업무용 PC 보안점검 조치 안내 "+Rules.Version);
                    Console.WriteLine("아래 명령은 직접 실행할 때 설정을 바꿉니다. 점검 프로그램은 이 명령을 자동 실행하지 않습니다. 관리자 권한이 필요한 단계는 각 항목에서 안내합니다.\n");
                    foreach(var c in new AuditEngine().Checks()) {var g=Guidance.For(c.Name);Console.WriteLine(c.Id+". "+c.Name+"\n1. 조치 방법\n"+g.Steps+"\n\n2. 항목의 의미\n"+g.Meaning+"\n\n3. 자세히\n기준: "+c.Criteria+"\n기존 권고: "+c.Advice+"\n조회 방법: "+c.Method+"\n\n");}
                    return 0;
                }
                if(args.Length>0&&args[0]=="--wmi-path")
                {
                    using(var search=new System.Management.ManagementObjectSearcher(
                        new System.Management.ManagementScope(@"\\.\root\cimv2"),
                        new System.Management.ObjectQuery("SELECT DriveType FROM Win32_LogicalDisk"),LocalSystem.StatusQueryOptions()))
                    using(var rows=search.Get())
                    {
                        int count=0;
                        foreach(System.Management.ManagementObject row in rows)using(row)
                        { Assert(row.Path!=null&&row.Path.IsInstance,"projected WMI result retains callable instance path");count++; }
                        Assert(count>0,"local disk regression exercised");
                    }
                    return 0;
                }
                if(args.Length>0&&args[0]=="--audit")
                {
                    Console.WriteLine("LOCAL READ-ONLY SMOKE START (no report saved)");
                    var info=AuditEngine.ReadInfo(x=>Console.WriteLine("INFO: "+x));
                    Console.WriteLine("INFO_FIELDS="+info.Count+" UNKNOWN="+info.Count(x=>x.Value.StartsWith("확인 불가")));
                    var a=new AuditEngine().Run(info,(p,n)=>Console.WriteLine(p+"% "+n),()=>false);
                    foreach(var f in a.Findings)Console.WriteLine(f.Id+" "+f.Name+": "+Labels.Of(f.Status)+(f.Status==Verdict.Unknown||f.Id==12||f.Id==15||f.Id==16||f.Id==19?" / "+f.Value:""));
                    Assert(a.Finished.HasValue&&a.Findings.Count==19,"local audit completed 19 items");return 0;
                }
                if(args.Length>0&&args[0]=="--blocked-path") {Throws(()=>new ReportStore(args[1]).Save("test","PC",DateTime.Now),"redirected or inaccessible directory rejected");return 0;}
                if(args.Length>0&&args[0]=="--example") {Console.Write(Report.Html(Example(),true));return 0;}
                WorkflowTests();
                var scanNow=new DateTime(2026,11,7,12,0,0);
                var scanRow=new System.Collections.Generic.Dictionary<string,object>();
                Assert(AuditEngine.ScanHistory(scanRow,scanNow).Contains("완료 기록 없음"),"missing scan history not inferred as recent");
                scanRow["QuickScanEndTime"]=scanNow.AddDays(-1);scanRow["FullScanEndTime"]=DateTime.MinValue;
                Assert(AuditEngine.ScanHistory(scanRow,scanNow).Contains("2026-11-06")&&AuditEngine.ScanHistory(scanRow,scanNow).Contains("날짜 확인 필요"),"quick scan and sentinel full scan distinguished");
                scanRow["FullScanEndTime"]=scanNow.AddHours(1);
                Assert(AuditEngine.ScanHistory(scanRow,scanNow).Contains("시각 이상"),"future scan timestamp flagged");
                Assert(Audit.Questions[2].Contains("6개월")&&Audit.Questions[3].Contains("담당자가 아니면")&&Audit.Questions[6].Contains("보안관리자")&&Audit.Questions[6].Contains("모름")&&!Audit.Questions[6].Contains("라이선스 위반"),"revised manual questions and policy wording");
                Assert(Labels.Of(Verdict.Partial)=="부분통과","partial Korean label");
                var msFinding=AuditEngine.MicrosoftLoginFinding();
                Assert(msFinding.Status==Verdict.Partial&&msFinding.Value.Contains("미검증")&&msFinding.Value.Contains("복구 정보"),"MS account type alone stays partial with security review");
                var partialAudit=Example();foreach(var f in partialAudit.Findings)f.Status=Verdict.Good;
                var partialFinding=partialAudit.Findings.Single(f=>f.Id==12);partialFinding.Status=msFinding.Status;partialFinding.Value=msFinding.Value;
                string partialHtml=Report.Html(partialAudit,false);
                Assert(partialHtml.Contains("<span class='badge Partial'>부분통과</span><strong>1</strong>")&&partialHtml.Contains("<span class='badge Good'>통과</span><strong>18</strong>"),"partial count separate from pass count");
                Assert(partialHtml.Contains("<h2 class='detail'>")&&partialHtml.Contains("<h3>12. 로그인 계정·암호 정책")&&partialHtml.Contains("<strong>12. 로그인 계정·암호 정책</strong>"),"partial remains in attention list and details");
                Assert(Guidance.For(partialFinding.Name).Steps.Contains("최근 로그인 활동")&&Guidance.For(partialFinding.Name).Steps.Contains("검토 의견"),"MS guide requires recorded security review");
                DateTime now=new DateTime(2026,11,6,12,0,0);string why;
                Assert(Rules.Age(null,now,3,7)==Verdict.Review,"missing timestamp requires manual review");
                Assert(Rules.Age(now.AddHours(1),now,3,7)==Verdict.Unknown,"future timestamp unknown");
                Assert(Rules.Age(now.AddDays(-3),now,3,7)==Verdict.Good,"signature 3-day boundary");
                Assert(Rules.Age(now.AddDays(-3).AddSeconds(-1),now,3,7)==Verdict.Review,"signature beyond 3 days");
                Assert(Rules.Age(now.AddDays(-7),now,3,7)==Verdict.Review,"signature 7-day boundary");
                Assert(Rules.Age(now.AddDays(-7).AddSeconds(-1),now,3,7)==Verdict.Weak,"signature older than 7 days");
                Assert(Rules.Age(now.AddDays(-45),now,45,45)==Verdict.Good,"update 45-day boundary");
                Assert(Rules.Age(now.AddDays(-46),now,45,45)==Verdict.Weak,"update older than 45 days");
                Assert(Rules.Os("Core",19045,"22H2",now,out why)==Verdict.Weak,"Windows 10 office baseline");
                Assert(Rules.Os("Core",26100,"24H2",now,out why)==Verdict.Weak,"Windows 11 expired release");
                Assert(Rules.Os("Core",26200,"25H2",now,out why)==Verdict.Good,"supported Home release");
                Assert(Rules.Os("Core",99999,"25H2",now,out why)==Verdict.Review,"unrecognized build never good");
                Assert(Rules.Os("EnterpriseS",19044,"21H2",now,out why)==Verdict.Review,"LTSC not conflated with Home");
                Assert(Rules.Os("Core",99999,"99H9",now,out why)==Verdict.Review,"unknown release never good");
                Assert(Rules.Lockout(10,900)==Verdict.Good,"lockout boundary");
                Assert(Rules.Lockout(0,900)==Verdict.Weak,"disabled lockout needs action");
                Assert(Rules.Lockout(10,0)==Verdict.Weak,"zero-duration lockout needs action");
                Assert(Rules.Lockout(10,UInt32.MaxValue)==Verdict.Good,"admin unlock accepted");
                                Assert(Rules.Password(9)==Verdict.Weak&&Rules.Password(12)==Verdict.Good,"password minimum boundary");
                Assert(Rules.Lockout(10,600)==Verdict.Weak,"ten minute lockout fails baseline");
                Assert(Rules.AutoLogon("")==Verdict.Good&&Rules.AutoLogon("0")==Verdict.Good&&Rules.AutoLogon("1")==Verdict.Weak&&Rules.AutoLogon("other")==Verdict.Review,"autologon absent enabled invalid");
                Assert(Rules.Encryption(1,1)==Verdict.Good&&Rules.Encryption(0,1)==Verdict.Weak&&Rules.Encryption(1,2)==Verdict.Weak&&Rules.Encryption(2,1)==Verdict.Review,"encrypted suspended progressing unknown");
                Assert(LocalSystem.AllowedStatusMethod(LocalSystem.Tpm,"IsReadyInformation")&&!LocalSystem.AllowedStatusMethod(LocalSystem.Tpm,"Clear")&&!LocalSystem.AllowedStatusMethod(LocalSystem.Encryption,"Encrypt")&&!LocalSystem.AllowedStatusMethod(LocalSystem.Cim,"GetProtectionStatus"),"WMI method scope blocks mutations");
                Throws(()=>LocalSystem.ScreenSetting(17),"screen SET action rejected");
                Assert(Labels.Of(Verdict.Good)=="통과"&&Labels.Of(Verdict.Weak)=="조치 필요"&&Labels.Of(Verdict.Review)=="수동 확인 필요"&&Labels.Of(Verdict.Unknown)=="확인 불가","four Korean labels");
                Assert(Rules.Tpm("2.0, 0, 1.38",true)==Verdict.Good&&Rules.Tpm("2.0",false)==Verdict.Weak&&Rules.Tpm("1.2",true)==Verdict.Weak,"TPM current ready and version");
                Assert(Rules.AutoUpdate(null,4)==Verdict.Good&&Rules.AutoUpdate(1,4)==Verdict.Weak&&Rules.AutoUpdate(null,1)==Verdict.Weak&&Rules.AutoUpdate(null,0)==Verdict.Unknown,"automatic update on off unknown");
                Assert(Rules.ScreenLock(true,false)==Verdict.Good&&Rules.ScreenLock(false,true)==Verdict.Good&&Rules.ScreenLock(false,false)==Verdict.Weak,"screen lock no eligible path needs action");
                Assert(!new AuditEngine().Checks().Any(c=>c.Name=="현재 계정·관리자 권한"||c.Name=="로컬 관리자 그룹 구성"),"administrator checks removed");
                Assert(LocalSystem.ClassifyLogin(true,"MicrosoftAccount")==LocalSystem.LoginKind.Microsoft&&LocalSystem.ClassifyLogin(false,"MicrosoftAccount")==LocalSystem.LoginKind.Local&&LocalSystem.ClassifyLogin(true,"Other")==LocalSystem.LoginKind.Other,"Windows internet provider requires actual connection");
                foreach(var c in new AuditEngine().Checks()) {
                    var guide=Guidance.For(c.Name);
                    Assert(guide.Steps.Contains("1)")&&!String.IsNullOrEmpty(guide.Meaning),"action and explanation: "+c.Name);
                    var finding=new Finding {Id=c.Id,Name=c.Name,Area=c.Area,Value="確認値",Criteria=c.Criteria,Advice=c.Advice,Method=c.Method};
                    string detail=Guidance.Detail(finding);
                    Assert(detail.IndexOf("1. 조치 방법")<detail.IndexOf("2. 항목의 의미")&&detail.IndexOf("2. 항목의 의미")<detail.IndexOf("3. 자세히")&&detail.Contains(c.Method),"detail order and original technical content: "+c.Name);
                }
                var example=Example();example.Institution="<script>alert('x')</script> & \"기관\"";example.Notes="<img src='https://example.invalid'>";
                string html=Report.Html(example,true);
                Assert(!html.Contains("<script>")&&!html.Contains("<img src="),"HTML injection encoded");
                Assert(System.Text.RegularExpressions.Regex.Matches(html,"<h4>1. 조치 방법</h4>").Count==example.Findings.Count(f=>f.Status!=Verdict.Good),"report includes actionable guides only for attention items");

                string detailHtml=html.Substring(html.IndexOf("4. 상세 점검 결과"),html.IndexOf("<h2>5.")-html.IndexOf("4. 상세 점검 결과"));
                foreach(var finding in example.Findings) {
                    string title="<h3>"+finding.Id+". "+Report.E(finding.Name)+" ";
                    Assert(detailHtml.Contains(title)==(finding.Status!=Verdict.Good),"detail visibility follows verdict: "+finding.Name);
                }
                Assert(!html.Contains("점검 시작")&&html.Contains("점검 완료"),"report removes start row and keeps completion");
                string pcTable=html.Substring(html.IndexOf("<table class='pcinfo'>"),html.IndexOf("<h2>2.")-html.IndexOf("<table class='pcinfo'>"));
                Assert(!pcTable.Contains("PC 이름")&&System.Text.RegularExpressions.Regex.Matches(html,"<th scope='row'>PC 이름</th>").Count==1,"PC name appears once in metadata");
                Assert(System.Text.RegularExpressions.Regex.Matches(pcTable,"<tr>").Count==(example.Info.Count)/2&&pcTable.Contains("colspan='3'"),"PC info pairs fields and spans odd final field");
                example.Info["Windows 로그인 계정"]="<img src=x>";
                string evenHtml=Report.Html(example,false);
                Assert(evenHtml.Contains("&lt;img src=x&gt;")&&!evenHtml.Contains("<img src=x>"),"paired PC values remain HTML escaped");
                foreach(var finding in example.Findings)finding.Status=Verdict.Good;
                string allGood=Report.Html(example,false);
                Assert(!allGood.Contains("<section class='finding'>")&&!allGood.Contains("class='detail'")&&allGood.Contains("상세 설명이 필요한 자동 점검 항목이 없습니다."),"all-pass report has no details or forced detail page");
                Assert(allGood.Contains("Windows 지원 상태")&&allGood.Contains("<strong>19</strong>"),"all-pass report retains summary names and counts");
                example.Info.Clear();
                Assert(Report.Html(example,false).Contains("추가 PC 정보가 없습니다."),"empty PC information handled");
                Assert(html.Contains("&lt;script&gt;")&&html.Contains("&amp;"),"HTML escaping retained");
                Assert(html.Contains("default-src 'none'")&&html.Contains("@media print")&&html.Contains("@page"),"offline CSP and print styles");
                Assert(html.Contains("PC 사용자")&&html.Contains("점검자"),"inspector and user separate");
                Assert(example.Findings.Count==19&&Enum.GetValues(typeof(Verdict)).Cast<Verdict>().Sum(v=>example.Findings.Count(x=>x.Status==v))==19,"all four statuses counted separately");
                Throws(()=>Report.Html(new Audit(),false),"unfinished audit cannot export");
                Assert(ReportStore.HostToken(@"..\../악성:PC") == "악성PC","host filename path injection removed");
                Throws(()=>new ReportStore(@"\\example.invalid\share").Save("x","PC",now),"UNC blocked before any file write");
                var store=new ReportStore();string first=store.Save("<html>한글</html>","테스트PC",now);string second=store.Save("second","테스트PC",now);
                Assert(Path.GetDirectoryName(first)==store.OutputDirectory,"report saved only in output directory");
                Assert(first!=second&&File.ReadAllText(first).Contains("한글"),"repeat save preserves original UTF-8 report");
                string source=File.ReadAllText(first);Assert(source=="<html>한글</html>","saved content exact");
                Application.EnableVisualStyles();using(var form=new MainForm()){form.CreateControl();Assert(form.Text=="업무용 PC 보안점검 도구","form construct and controls");}
                Console.WriteLine("TOTAL_PASS="+passed);return 0;
            }
            catch(Exception e){Console.Error.WriteLine(e.ToString());return 1;}
        }
    }
}









