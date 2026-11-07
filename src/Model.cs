using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace OfficePcAudit
{
    public enum Verdict { Good, Weak, Review, Unknown, Partial }
    public static class Labels
    {
        public static string Of(Verdict v)
        {
            switch(v) { case Verdict.Good: return "통과"; case Verdict.Weak: return "조치 필요";
                case Verdict.Review: return "수동 확인 필요"; case Verdict.Partial: return "부분통과"; default: return "확인 불가"; }
        }
        public static string Time(DateTime d) { return d.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture); }
    }
    public sealed class Finding
    {
        public int Id; public string Area, Name, Value, Criteria, Advice, Method;
        public Verdict Status; public DateTime Time = DateTime.Now;
    }
    public sealed class Audit
    {
        public DateTime Started = DateTime.Now; public DateTime? Finished;
        public readonly Dictionary<string,string> Info = new Dictionary<string,string>();
        public readonly List<Finding> Findings = new List<Finding>();
        public string Institution = "", Inspector = "", PcUser = "", Notes = "", FollowUp = "";
        public readonly List<ManualAnswer> Manual = new List<ManualAnswer>();
        public static readonly string[] Questions = {
            "개인정보 파일의 보유 필요성을 확인하고 불필요한 자료를 정리했습니까?",
            "보관·전달하는 개인정보 파일에 적절한 암호화와 접근 제한을 적용했습니까?",
            "최근 6개월 이내에 중요 자료를 백업하고 복구 가능 여부를 확인했습니까?",
            "퇴사자·미사용 계정과 불필요한 관리자 권한을 정리했습니까? (계정·권한 관리 담당자가 아니면 ‘해당 없음’을 선택해 주세요.)",
            "자동 로그인 없이 암호·PIN·생체 인증을 거치며, 암호가 길고 고유하고 타인과 공유하지 않는지 확인했습니까? (12자 이상 권장, 암호 입력 금지)",
            "공유폴더·원격접속의 업무상 필요성과 접근 권한을 확인했습니까?",
            "사용 중인 타사 백신의 업무용 라이선스를 구매·취득했거나 구매 없이 업무용 사용이 허용되는지 확인했습니까? (라이선스를 확보하지 않았거나 이용 조건을 모르면 보안관리자에게 확인해 주세요. 확인 전에는 ‘모름’을 선택해 주세요. 타사 백신을 사용하지 않으면 ‘해당 없음’을 선택해 주세요.)",
            "보안 사고·악성코드 의심 증상이 없는지 확인했습니까?"
        };
        public Audit() { foreach (string q in Questions) Manual.Add(new ManualAnswer { Question = q, Answer = "모름" }); }
    }
    public sealed class ManualAnswer { public string Question, Answer; }
    public static class Rules
    {
        public const string Version = "1.0.0 / 2026-11-07";
        public static Verdict Age(DateTime? observed, DateTime now, double goodDays, double weakDays)
        {
            if (!observed.HasValue) return Verdict.Review;
            if (observed.Value.Year < 2000 || observed.Value > now.AddMinutes(5)) return Verdict.Unknown;
            double age = (now - observed.Value).TotalDays;
            return age <= goodDays ? Verdict.Good : age <= weakDays ? Verdict.Review : Verdict.Weak;
        }
        public static Verdict Os(string edition, int build, string release, DateTime now, out string reason)
        {
            bool homePro = new [] {"Core","CoreSingleLanguage","CoreCountrySpecific","Professional","ProfessionalN","ProfessionalEducation","ProfessionalWorkstation"}.Contains(edition);
            if (!homePro) { reason="Home/Pro 이외 에디션입니다. LTSC·조직용 수명 주기는 자동 판정하지 않습니다."; return Verdict.Review; }
            if (build < 22000 && build >= 10240) { reason="Windows 10 일반 지원 종료. 조직 운영기준 미충족. ESU 적용 여부는 검증하지 않았습니다."; return Verdict.Weak; }
            // Microsoft release-health table, verified 2026-11-06. Unknown builds/releases never pass.
            var ends = new Dictionary<string,DateTime> {
                {"21H2",new DateTime(2023,10,10)}, {"22H2",new DateTime(2024,10,8)},
                {"23H2",new DateTime(2025,11,11)}, {"24H2",new DateTime(2026,10,13)},
                {"25H2",new DateTime(2027,10,12)}, {"26H1",new DateTime(2028,3,14)}, {"26H2",new DateTime(2028,10,10)} };
            var builds = new Dictionary<string,int> { {"21H2",22000},{"22H2",22621},{"23H2",22631},{"24H2",26100},{"25H2",26200},{"26H1",28000},{"26H2",26300} };
            if (!ends.ContainsKey(release) || !builds.ContainsKey(release) || builds[release] != build) { reason="내장 기준표에 없는 버전·빌드 조합입니다. 최신 지원기간을 별도로 확인하십시오."; return Verdict.Review; }
            reason="Home/Pro 지원 종료일: " + ends[release].ToString("yyyy-MM-dd") + ". 기준표 확인일: 2026-11-06. ESU·Insider는 판정 범위 밖입니다.";
            return now.Date > ends[release] ? Verdict.Weak : Verdict.Good;
        }
        public static Verdict Lockout(uint threshold, uint duration)
        { return threshold > 0 && threshold <= 10 && (duration == UInt32.MaxValue || duration >= 900) ? Verdict.Good : Verdict.Weak; }
        public static Verdict AutoUpdate(int? policy,int level)
        { return policy==1||level==1?Verdict.Weak:level>=2&&level<=4?Verdict.Good:Verdict.Unknown; }
        public static Verdict ScreenLock(bool machine,bool saver) { return machine||saver?Verdict.Good:Verdict.Weak; }
        public static Verdict Password(uint length) { return length>=12?Verdict.Good:Verdict.Weak; }
        public static Verdict Tpm(string spec,bool ready)
        { return ready&&!String.IsNullOrEmpty(spec)&&spec.Split(',')[0].Trim()=="2.0"?Verdict.Good:Verdict.Weak; }
        public static Verdict AutoLogon(string value)
        { return value=="1"?Verdict.Weak:String.IsNullOrEmpty(value)||value=="0"?Verdict.Good:Verdict.Review; }
        public static Verdict Encryption(int protection,int conversion)
        { return protection==2?Verdict.Review:protection==1&&conversion==1?Verdict.Good:Verdict.Weak; }
    }
}






