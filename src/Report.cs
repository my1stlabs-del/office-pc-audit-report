using System;
using System.Linq;
using System.Text;

namespace OfficePcAudit
{
    public static class Report
    {
        public static string E(string s) { return (s??"").Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace("\"","&quot;").Replace("'","&#39;"); }
        static void Row(StringBuilder b,string name,string value)
        { b.Append("<tr><th scope='row'>").Append(E(name)).Append("</th><td>").Append(E(value)).Append("</td></tr>"); }
        static string Badge(Verdict v) {return "<span class='badge "+v+"'>"+Labels.Of(v)+"</span>";}
        public static string Html(Audit a,bool example)
        {
            if(!a.Finished.HasValue)throw new InvalidOperationException("완료되지 않은 점검은 저장할 수 없습니다.");
            var b=new StringBuilder(40000);
            b.Append(@"<!doctype html><html lang='ko'><head><meta charset='utf-8'>
<meta http-equiv='Content-Security-Policy' content=""default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"">
<meta name='viewport' content='width=device-width, initial-scale=1'><title>업무용 PC 보안점검 결과보고서</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#eef2f6;color:#172537;font:14px/1.65 'Malgun Gothic','맑은 고딕',sans-serif}main{max-width:1000px;margin:32px auto;background:white;padding:44px 50px}h1{font-size:29px;line-height:1.4;margin:10px 0 24px}h2{font-size:20px;border-bottom:2px solid #244d70;padding-bottom:8px;margin:32px 0 14px}h3{font-size:16px;margin:0 0 12px}p{margin:10px 0}.eyebrow{color:#365b79;font-weight:bold;letter-spacing:2px}.subtle{color:#536276;font-size:12px}.notice{padding:12px 16px;background:#f1f5f8;border-left:4px solid #486e8b}table{width:100%;border-collapse:collapse;table-layout:fixed;margin:12px 0}th,td{border:1px solid #c8d1db;text-align:left;vertical-align:top;padding:9px 12px;overflow-wrap:anywhere;word-break:break-word;white-space:pre-wrap}th{background:#f2f5f8;font-weight:600;width:25%}thead th{width:auto}.pcinfo th{width:auto}.pcinfo th,.pcinfo td{padding:7px 10px}.summary{display:flex;flex-wrap:wrap;gap:10px;margin:18px 0}.count{border:1px solid #ccd6df;border-radius:6px;padding:10px 16px;min-width:120px}.count strong{display:block;font-size:24px}.badge{font-weight:bold;display:inline-block;padding:2px 8px;border:1px solid currentColor;border-radius:4px}.Good{color:#116345}.Weak{color:#a22727}.Review{color:#815500}.Partial{color:#815500}.Unknown{color:#5b4a7e}.finding{border:1px solid #c8d1db;padding:16px;margin:16px 0;break-inside:avoid-page;page-break-inside:avoid}.finding table{margin-bottom:0}.guide{white-space:pre-wrap;overflow-wrap:anywhere}h4{font-size:15px;margin:18px 0 8px}.finding th{width:20%}.reviewtext{white-space:pre-wrap;overflow-wrap:anywhere;min-height:80px;border:1px solid #c8d1db;padding:14px}.manual th:first-child{width:8%}.manual th:last-child{width:16%}.manual th:nth-child(2){width:76%}li{margin:6px 0}footer{border-top:1px solid #c8d1db;margin-top:30px;padding-top:12px}.screen{padding:10px 0;color:#536276}.example{color:#a22727;font-weight:bold;border:2px solid #a22727;padding:10px}
@page{size:A4;margin:16mm 14mm} @media print{body{background:white;font-size:10pt;line-height:1.5}main{max-width:none;margin:0;padding:0}h1{font-size:23pt}h2{font-size:15pt;break-after:avoid-page;page-break-after:avoid}h3{break-after:avoid-page;page-break-after:avoid}thead{display:table-header-group}tr{break-inside:avoid-page;page-break-inside:avoid}.screen{display:none}.detail{break-before:page;page-break-before:always}.finding{padding:10px;margin:12px 0}.count{min-width:90px;padding:6px 12px}th,td{padding:6px 8px}.badge{color:#172537}footer{font-size:9pt}.reviewtext{min-height:65px}}
</style></head><body><main><div class='eyebrow'>OFFICE PC SECURITY CHECK</div><h1>업무용 PC 보안점검<br>결과보고서</h1>");
            if(example)b.Append("<p class='example'>보고서 형식 예시 · 가상 데이터 · 실제 PC 점검 결과가 아닙니다.</p>");
            b.Append("<p class='screen'>이 파일은 독립형 HTML입니다. Edge 또는 Chrome에서 Ctrl+P → A4로 인쇄하거나 ‘PDF로 저장’을 선택하십시오. 머리글·바닥글은 필요에 따라 끄십시오.</p><table><tbody>");
            Row(b,"기관명",a.Institution);Row(b,"점검자",a.Inspector);Row(b,"PC 사용자",a.PcUser);
            Row(b,"PC 이름",a.Info.ContainsKey("PC 이름")?a.Info["PC 이름"]:"");
            Row(b,"점검 완료",Labels.Time(a.Finished.Value));
            Row(b,"기준 버전",Rules.Version);b.Append("</tbody></table><p class='notice'>로컬 설정 조회에 따른 내부 점검 기록입니다. 보안 인증·침해 부재·법적 의무 충족을 보증하지 않습니다. 자동 점검 결과와 직원의 수동 확인은 별도로 기록합니다.</p>");
            b.Append("<h2>1. 시스템 기본 정보</h2><table class='pcinfo'><colgroup><col style='width:18%'><col style='width:32%'><col style='width:18%'><col style='width:32%'></colgroup><tbody>");
            var pcInfo=a.Info.Where(x=>x.Key!="PC 이름").ToList();
            for(int i=0;i<pcInfo.Count;i+=2)
            {
                b.Append("<tr><th scope='row'>").Append(E(pcInfo[i].Key)).Append("</th><td").Append(i+1==pcInfo.Count?" colspan='3'":"").Append(">").Append(E(pcInfo[i].Value)).Append("</td>");
                if(i+1<pcInfo.Count)b.Append("<th scope='row'>").Append(E(pcInfo[i+1].Key)).Append("</th><td>").Append(E(pcInfo[i+1].Value)).Append("</td>");
                b.Append("</tr>");
            }
            if(pcInfo.Count==0)b.Append("<tr><td colspan='4'>추가 PC 정보가 없습니다.</td></tr>");
            b.Append("</tbody></table>");
            b.Append("<h2>2. 자동 점검 요약</h2><p>전체 ").Append(a.Findings.Count).Append("개 항목 · 통과: 기준 충족 · 부분통과: 계정 유형 확인·보안 검토 필요 · 조치 필요: 기준 미달 · 수동 확인 필요: 사람의 판단 필요 · 확인 불가: 조회 실패. 통과는 명시된 점검 범위에 한정됩니다. 보안 점수는 산정하지 않습니다.</p><div class='summary'>");
            foreach(Verdict v in Enum.GetValues(typeof(Verdict))) b.Append("<div class='count'>").Append(Badge(v)).Append("<strong>").Append(a.Findings.Count(x=>x.Status==v)).Append("</strong></div>");
            b.Append("</div><table><thead><tr><th style='width:8%'>번호</th><th style='width:22%'>영역</th><th style='width:48%'>항목</th><th style='width:22%'>판정</th></tr></thead><tbody>");
            foreach(var f in a.Findings)b.Append("<tr><td>").Append(f.Id).Append("</td><td>").Append(E(f.Area)).Append("</td><td>").Append(E(f.Name)).Append("</td><td>").Append(Badge(f.Status)).Append("</td></tr>");b.Append("</tbody></table>");
            b.Append("<h2>3. 우선 검토 항목</h2><ul>");var attention=a.Findings.Where(x=>x.Status!=Verdict.Good).OrderBy(x=>x.Status==Verdict.Weak?0:x.Status==Verdict.Unknown?1:2).ToList();
            if(attention.Count==0)b.Append("<li>자동 판정에서 우선 검토 항목이 없습니다. 수동 점검은 별도로 확인하십시오.</li>");
            foreach(var f in attention)b.Append("<li>").Append(Badge(f.Status)).Append(" <strong>").Append(f.Id).Append(". ").Append(E(f.Name)).Append("</strong> — ").Append(E(Guidance.For(f.Name).Steps.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries)[0])).Append(" (전체 방법은 아래 상세 항목 참고)</li>");b.Append("</ul>");
            b.Append(attention.Count>0?"<h2 class='detail'>4. 상세 점검 결과</h2>":"<h2>4. 상세 점검 결과</h2>");
            b.Append("<p>통과 항목은 자동 점검 요약에만 표시합니다.</p>");
            if(attention.Count==0)b.Append("<p>상세 설명이 필요한 자동 점검 항목이 없습니다. 직원 수동 확인표를 확인하십시오.</p>");
            foreach(var f in a.Findings.Where(x=>x.Status!=Verdict.Good)){b.Append("<section class='finding'><h3>").Append(f.Id).Append(". ").Append(E(f.Name)).Append(" ").Append(Badge(f.Status)).Append("</h3>");
                var guide=Guidance.For(f.Name);
                b.Append("<h4>1. 조치 방법</h4><p class='guide'>");
                if(f.Status==Verdict.Unknown)b.Append("조회에 실패했습니다. 아래 화면에서 실제 상태를 먼저 확인하세요. 권한 오류라면 관리자 권한으로 재점검합니다.\n");
                b.Append(E(guide.Steps)).Append("</p><h4>2. 항목의 의미</h4><p class='guide'>").Append(E(guide.Meaning)).Append("</p><h4>3. 자세히</h4><table><tbody>");Row(b,"영역",f.Area);Row(b,"확인된 값",f.Value);Row(b,"판단 기준",f.Criteria);Row(b,"조치 권고",f.Advice);Row(b,"점검 방법",f.Method);Row(b,"점검 시각",Labels.Time(f.Time));b.Append("</tbody></table></section>");}
            b.Append("<h2>5. 직원 수동 확인표</h2><p>아래 답변은 직접 입력한 내용이며 자동으로 검증되지 않았습니다. 수동 ‘미흡’·‘모름’·‘미응답’ 답변은 자동 판정 건수에 합산하지 않습니다.</p><table class='manual'><thead><tr><th>번호</th><th>확인 내용</th><th>직접 응답</th></tr></thead><tbody>");
            int n=0;foreach(var m in a.Manual)b.Append("<tr><td>").Append(++n).Append("</td><td>").Append(E(m.Question)).Append("</td><td>").Append(E(m.Answer)).Append("</td></tr>");b.Append("</tbody></table>");
            b.Append("<h2>6. 점검자 검토 의견</h2><div class='reviewtext'>").Append(E(a.Notes)).Append("</div><h2>7. 후속 조치 사항</h2><div class='reviewtext'>").Append(E(a.FollowUp)).Append("</div>");
            b.Append(@"<h2>8. 점검 방법과 한계</h2><ul>
<li>프로그램이 직접 사용하는 조회는 로컬 Windows API·WMI·COM·읽기 전용 레지스트리입니다. 인터넷 검색·업데이트 검색·원격 접속·설정 변경·자동 권한 상승을 구현하지 않았습니다. 이 보고서는 실행 중 통신을 계측한 증명서는 아닙니다.</li>
<li>현재 실행 계정에 허용된 정보를 조회합니다. TPM·암호화 상세 조회에는 관리자 권한이 필요할 수 있습니다. 공급자 오류·권한 부족·15초 조회 시간 초과는 확인 불가로 처리합니다. 시간 초과한 운영체제 조회가 즉시 취소된다고 보장하지 않습니다.</li>
<li>Windows Update는 로컬 QFE 기록 일부만 조회합니다. 최신 보안 업데이트 적용 여부, ESU 가입·유효성, 서버의 최신 버전과 비교하지 않았습니다.</li>
<li>Defender 외 제품의 등록 정보는 실제 설치·라이선스·정의 최신성을 보장하지 않습니다. 타사 백신의 업무용 사용 승인은 별도 확인 사항입니다.</li>
<li>로컬 계정 정책은 현재 암호의 안전성이나 Windows Hello·Microsoft 계정 정책을 증명하지 않습니다. 도메인·MDM 정책의 전체 적용 결과는 검증하지 않았습니다.</li>
<li>개인정보 파일 내용·파일 목록·암호·인증 토큰·브라우저 기록·제품키·하드웨어 일련번호·IP·MAC 주소는 수집하지 않습니다. 보고서에는 PC 이름·로그인 계정·직접 입력한 이름 등 내부 정보가 포함됩니다.</li>
<li>쓰기 허용 범위는 사용자가 요청한 결과출력 폴더와 HTML 보고서입니다. Windows·런타임·백신이 남기는 부수 기록과 사용자가 브라우저에서 인쇄·저장하는 PDF는 프로그램의 직접 쓰기 제한 범위 밖입니다.</li>
<li>저장 HTML은 편집 가능한 파일입니다. 전자서명·위변조 방지 기능이 없으므로 공식 보관본은 조직의 문서관리 절차에 따라 보관하십시오.</li>
</ul><footer>업무용 PC 보안점검 도구 · 기준 ");
            b.Append(E(Rules.Version)).Append(" · 호스트 시스템 시계를 사용합니다.</footer></main></body></html>");return b.ToString();
        }
    }
}








