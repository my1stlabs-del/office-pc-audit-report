using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace OfficePcAudit
{
    public sealed class MainForm : Form
    {
        readonly Color Navy=Color.FromArgb(27,48,70),Muted=Color.FromArgb(79,96,115);
        readonly TextBox institution=new TextBox(),inspector=new TextBox(),pcUser=new TextBox(),notes=new TextBox(),followup=new TextBox();
        readonly TextBox infoText=new TextBox(),detail=new TextBox();
        readonly Button start=new Button(),cancel=new Button(),save=new Button();
        readonly Label progressText=new Label(),summary=new Label();
        readonly ProgressBar progress=new ProgressBar();
        readonly DataGridView grid=new DataGridView();
        readonly ComboBox filter=new ComboBox();
        readonly List<ComboBox> answers=new List<ComboBox>();
        readonly BackgroundWorker worker=new BackgroundWorker { WorkerReportsProgress=true,WorkerSupportsCancellation=true };
        Dictionary<string,string> info=new Dictionary<string,string>();
        Audit audit;

        internal enum ScanState { Ready, Scanning, Cancelling, Completed, Cancelled, Failed }
        ScanState state=ScanState.Ready;
        readonly Panel[] pages={new Panel(),new Panel(),new Panel(),new Panel()};
        readonly Label steps=new Label(),manualProgress=new Label(),exportSummary=new Label();
        readonly Button previous=new Button(),next=new Button();
        int step;
        internal int CurrentStep { get { return step; } }
        internal ScanState CurrentScanState { get { return state; } }
        bool IsComplete { get { return audit!=null&&audit.Finished.HasValue; } }
        public MainForm()
        {
            Text="업무용 PC 보안점검 도구";Font=new Font("맑은 고딕",10);AutoScaleMode=AutoScaleMode.Dpi;
            MinimumSize=new Size(960,740);Size=new Size(1240,900);StartPosition=FormStartPosition.CenterScreen;BackColor=Color.FromArgb(243,246,249);
            var root=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=5,Padding=new Padding(20)};
            foreach(int h in new[]{65,46})root.RowStyles.Add(new RowStyle(SizeType.Absolute,h));
            root.RowStyles.Add(new RowStyle(SizeType.Percent,100));root.RowStyles.Add(new RowStyle(SizeType.Absolute,52));root.RowStyles.Add(new RowStyle(SizeType.Absolute,28));Controls.Add(root);
            root.Controls.Add(new Label {Text="업무용 PC 보안점검",Font=new Font(Font.FontFamily,20,FontStyle.Bold),ForeColor=Color.White,BackColor=Navy,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft,Padding=new Padding(15,0,0,0)},0,0);
            steps.Dock=DockStyle.Fill;steps.TextAlign=ContentAlignment.MiddleLeft;steps.ForeColor=Navy;root.Controls.Add(steps,0,1);
            var content=new Panel {Dock=DockStyle.Fill};root.Controls.Add(content,0,2);
            foreach(var page in pages){page.Dock=DockStyle.Fill;content.Controls.Add(page);}
            var nav=new FlowLayoutPanel {Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft,Padding=new Padding(0,7,0,0)};
            next.Size=new Size(210,36);previous.Size=new Size(100,36);previous.Text="이전";nav.Controls.Add(next);nav.Controls.Add(previous);root.Controls.Add(nav,0,3);
            previous.Click+=(sender,e)=>Navigate(step-1);next.Click+=(sender,e)=>Navigate(step+1);
            root.Controls.Add(new Label {Text="저장: 프로그램 폴더의 결과출력"+"  |  HTML을 브라우저에서 Ctrl+P로 인쇄·PDF 저장  |  기준 "+Rules.Version,Dock=DockStyle.Fill,ForeColor=Muted,Font=new Font(Font.FontFamily,9)},0,4);
            pages[0].AutoScroll=true;
            pages[0].Controls.Add(new Label {AutoSize=true,MaximumSize=new Size(850,0),Padding=new Padding(25),Font=new Font(Font.FontFamily,12),Text="점검 안내\r\n\r\n① 점검 안내 → ② 자동 확인 → ③ 수동 확인 → ④ 정보 입력 및 출력\r\n\r\nWindows 설정을 조회하며 자동으로 변경하지 않습니다.\r\n자동 확인에서는 PC 기본 정보와 19개 항목을 조회합니다.\r\n수동 확인에서는 8개 질문에 응답합니다. 모르는 항목도 그대로 기록할 수 있습니다.\r\n\r\n보고서에는 PC 이름·로그인 계정·입력한 이름과 점검 결과가 기록됩니다.\r\n암호·개인정보 파일 내용은 입력하지 마십시오.\r\n보고서는 마지막 단계에서 저장할 때만 생성합니다.\r\n\r\n‘자동 확인으로’를 누른 뒤 점검을 시작하십시오."});
            var automatic=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=4};
            automatic.RowStyles.Add(new RowStyle(SizeType.Absolute,110));automatic.RowStyles.Add(new RowStyle(SizeType.Absolute,54));automatic.RowStyles.Add(new RowStyle(SizeType.Absolute,40));automatic.RowStyles.Add(new RowStyle(SizeType.Percent,100));pages[1].Controls.Add(automatic);
            infoText.Dock=DockStyle.Fill;infoText.Multiline=true;infoText.ReadOnly=true;infoText.ScrollBars=ScrollBars.Vertical;infoText.BackColor=Color.White;infoText.Text="점검 시작 시 PC 기본 정보를 조회합니다.";automatic.Controls.Add(infoText,0,0);
            var actions=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=3};actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,145));actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,95));actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            ConfigureButton(start,"점검 시작",true);start.Click+=(sender,e)=>StartScan();ConfigureButton(cancel,"중단",false);cancel.Click+=(sender,e)=>RequestCancel();
            progressText.Dock=DockStyle.Fill;progressText.TextAlign=ContentAlignment.MiddleLeft;actions.Controls.Add(start,0,0);actions.Controls.Add(cancel,1,0);actions.Controls.Add(progressText,2,0);automatic.Controls.Add(actions,0,1);
            var status=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2};status.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));status.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,170));summary.Dock=DockStyle.Fill;summary.TextAlign=ContentAlignment.MiddleLeft;progress.Dock=DockStyle.Fill;progress.Margin=new Padding(0,10,0,8);status.Controls.Add(summary,0,0);status.Controls.Add(progress,1,0);automatic.Controls.Add(status,0,2);
            var results=new Panel {Dock=DockStyle.Fill};automatic.Controls.Add(results,0,3);
            var resultLayout=new TableLayoutPanel {Dock=DockStyle.Fill,RowCount=2,ColumnCount=1};resultLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,38));resultLayout.RowStyles.Add(new RowStyle(SizeType.Percent,100));results.Controls.Add(resultLayout);
            var filterBar=new FlowLayoutPanel {Dock=DockStyle.Fill};filterBar.Controls.Add(new Label {Text="표시 항목",AutoSize=true,Margin=new Padding(5,7,8,0)});
            filter.DropDownStyle=ComboBoxStyle.DropDownList;filter.Items.AddRange(new object[]{"전체","조치 필요","부분통과","수동 확인 필요","확인 불가","통과"});filter.SelectedIndex=0;filter.SelectedIndexChanged+=(s,e)=>RefreshGrid();filter.Width=180;filterBar.Controls.Add(filter);resultLayout.Controls.Add(filterBar,0,0);
            var split=new SplitContainer {Size=new Size(1120,350),Dock=DockStyle.Fill,Orientation=Orientation.Vertical,SplitterDistance=650,Panel1MinSize=320,Panel2MinSize=260};resultLayout.Controls.Add(split,0,1);
            grid.Dock=DockStyle.Fill;grid.ReadOnly=true;grid.AllowUserToAddRows=false;grid.AllowUserToDeleteRows=false;grid.AllowUserToResizeRows=false;grid.RowHeadersVisible=false;grid.MultiSelect=false;grid.SelectionMode=DataGridViewSelectionMode.FullRowSelect;grid.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill;grid.BackgroundColor=Color.White;grid.BorderStyle=BorderStyle.None;grid.AutoSizeRowsMode=DataGridViewAutoSizeRowsMode.AllCells;grid.DefaultCellStyle.WrapMode=DataGridViewTriState.True;
            grid.Columns.Add("Id","번호");grid.Columns[0].FillWeight=12;grid.Columns.Add("Area","영역");grid.Columns[1].FillWeight=31;grid.Columns.Add("Name","점검 항목");grid.Columns[2].FillWeight=65;grid.Columns.Add("State","판정");grid.Columns[3].FillWeight=37;
            foreach(DataGridViewColumn column in grid.Columns)column.SortMode=DataGridViewColumnSortMode.NotSortable;
            grid.SelectionChanged+=(s,e)=>ShowFinding();split.Panel1.Controls.Add(grid);
            detail.Dock=DockStyle.Fill;detail.Multiline=true;detail.ReadOnly=true;detail.ScrollBars=ScrollBars.Vertical;detail.BackColor=Color.White;detail.BorderStyle=BorderStyle.FixedSingle;detail.Text="점검 후 항목을 선택하면 조치 방법 → 쉬운 의미 → 자세한 정보를 볼 수 있습니다.";split.Panel2.Controls.Add(detail);

            var manual=new Panel {Dock=DockStyle.Fill};pages[2].Controls.Add(manual);manualProgress.Dock=DockStyle.Top;manualProgress.Height=42;manualProgress.Padding=new Padding(12,8,0,0);pages[2].Controls.Add(manualProgress);
            var manualTable=new TableLayoutPanel {Dock=DockStyle.Fill,AutoScroll=true,ColumnCount=2,Padding=new Padding(12)};
            manualTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));manualTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,130));manual.Controls.Add(manualTable);
            int row=0;foreach(string question in Audit.Questions)
            {
                manualTable.RowStyles.Add(new RowStyle(SizeType.Absolute,76));
                manualTable.Controls.Add(new Label {Text=(row+1)+". "+question,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft,Padding=new Padding(0,0,15,0)},0,row);
                var box=new ComboBox {DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Top,Margin=new Padding(5,20,5,5)};
                box.Items.AddRange(new object[]{"선택해 주세요","모름","확인","미흡","해당 없음"});box.SelectedIndex=0;manualTable.Controls.Add(box,1,row);answers.Add(box);box.SelectedIndexChanged+=(s,e)=>UpdateManual();row++;
            }
            manualTable.RowStyles.Add(new RowStyle(SizeType.Absolute,40));manualTable.Controls.Add(new Label {Text="직접 응답은 자동 검증하지 않습니다. 실제 암호·개인정보 파일 내용은 입력하지 마십시오.",Dock=DockStyle.Fill,ForeColor=Muted},0,row);manualTable.SetColumnSpan(manualTable.GetControlFromPosition(0,row),2);

            var output=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=4};output.RowStyles.Add(new RowStyle(SizeType.Absolute,85));output.RowStyles.Add(new RowStyle(SizeType.Absolute,85));output.RowStyles.Add(new RowStyle(SizeType.Percent,100));output.RowStyles.Add(new RowStyle(SizeType.Absolute,48));pages[3].Controls.Add(output);
            exportSummary.Dock=DockStyle.Fill;output.Controls.Add(exportSummary,0,0);
            var fields=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=6,RowCount=2};for(int i=0;i<6;i++)fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,i%2==0?10:23.333f));
            AddField(fields,"기관명",institution,0);AddField(fields,"점검자",inspector,2);AddField(fields,"PC 사용자",pcUser,4);
            var note=new Label {Text="PC 사용자는 실제 사용하는 분의 이름입니다. 이름·PC 이름·계정 정보가 보고서에 기록됩니다.",Dock=DockStyle.Fill,ForeColor=Muted};fields.Controls.Add(note,0,1);fields.SetColumnSpan(note,6);output.Controls.Add(fields,0,1);
            var review=new Panel {Dock=DockStyle.Fill};output.Controls.Add(review,0,2);
            var reviewLayout=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=4,Padding=new Padding(12)};
            reviewLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,30));reviewLayout.RowStyles.Add(new RowStyle(SizeType.Percent,50));reviewLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,30));reviewLayout.RowStyles.Add(new RowStyle(SizeType.Percent,50));review.Controls.Add(reviewLayout);
            reviewLayout.Controls.Add(new Label {Text="점검자 검토 의견 (자동 결과는 유지되며 예외 사유를 여기에 기록합니다.)",Dock=DockStyle.Fill},0,0);SetupNotes(notes);reviewLayout.Controls.Add(notes,0,1);
            reviewLayout.Controls.Add(new Label {Text="후속 조치 사항 (담당자·예정일·완료 내용 등)",Dock=DockStyle.Fill},0,2);SetupNotes(followup);reviewLayout.Controls.Add(followup,0,3);

            ConfigureButton(save,"HTML 보고서 저장",true);save.Click+=(sender,e)=>SaveReport();output.Controls.Add(save,0,3);
            worker.DoWork+=DoWork;worker.RunWorkerCompleted+=Completed;
            worker.ProgressChanged+=(sender,e)=>{if(IsDisposed||state!=ScanState.Scanning)return;progress.Value=Math.Max(0,Math.Min(100,e.ProgressPercentage));progressText.Text=Convert.ToString(e.UserState);};
            FormClosing+=(sender,e)=>{if(worker.IsBusy)worker.CancelAsync();};
            UpdateManual();Navigate(0);SetScanState(ScanState.Ready,"점검 시작을 누르십시오.");
        }
        void AddField(TableLayoutPanel table,string label,TextBox input,int col)
        {table.Controls.Add(new Label {Text=label,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft},col,0);input.Dock=DockStyle.Fill;input.MaxLength=120;table.Controls.Add(input,col+1,0);}
        void ConfigureButton(Button b,string text,bool primary)
        {b.Text=text;b.Dock=DockStyle.Fill;b.FlatStyle=FlatStyle.Flat;b.BackColor=primary?Navy:Color.White;b.ForeColor=primary?Color.White:Navy;b.Margin=new Padding(0,0,8,0);}
        static void SetupNotes(TextBox b) {b.Multiline=true;b.ScrollBars=ScrollBars.Vertical;b.Dock=DockStyle.Fill;b.MaxLength=8000;}

        void StartScan()
        {
            if(worker.IsBusy)return;
            if(audit!=null&&MessageBox.Show(this,"이전 자동 결과를 새 결과로 바꿉니다. 저장하지 않은 결과는 사라집니다. 계속하시겠습니까?","다시 점검",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;
            audit=null;RefreshGrid();detail.Clear();progress.Value=0;
            SetScanState(ScanState.Scanning,"PC 기본 정보를 조회합니다…");worker.RunWorkerAsync();
        }
        internal void RequestCancel()
        {
            if(state!=ScanState.Scanning)return;
            worker.CancelAsync();SetScanState(ScanState.Cancelling,"중단 요청 중 · Windows 내부 조회는 종료까지 남을 수 있습니다.");
        }
        void DoWork(object sender,DoWorkEventArgs e)
        {
            try {
                var latest=AuditEngine.ReadInfo(name=>worker.ReportProgress(0,"기본 정보: "+name),()=>worker.CancellationPending);
                if(worker.CancellationPending){e.Cancel=true;return;}
                e.Result=new AuditEngine().Run(latest,(p,n)=>worker.ReportProgress(p,n),()=>worker.CancellationPending);
            } catch(OperationCanceledException){e.Cancel=true;}
        }
        void Completed(object sender,RunWorkerCompletedEventArgs e)
        {
            if(IsDisposed||Disposing)return;
            if(e.Error!=null){SetScanState(ScanState.Failed,"자동 확인 실패: "+LocalSystem.Error(e.Error)+" 다시 점검을 눌러 재시도하십시오.");return;}
            if(e.Cancelled){SetScanState(ScanState.Cancelled,"자동 확인을 중단했습니다. 다시 시작할 수 있습니다.");return;}
            audit=(Audit)e.Result;info=audit.Info;infoText.Text=String.Join(Environment.NewLine,info.Select(x=>x.Key+": "+x.Value));RefreshGrid();
            if(!IsComplete){SetScanState(ScanState.Cancelled,"중단됨 · 일부 결과는 참고용이며 저장은 불가합니다.");return;}
            progress.Value=100;SetScanState(ScanState.Completed,"자동 확인 완료 · 결과를 살펴본 뒤 수동 확인으로 이동하십시오.");
        }
        internal void SetScanState(ScanState value,string message)
        {
            state=value;bool busy=value==ScanState.Scanning||value==ScanState.Cancelling;
            start.Enabled=!busy;start.Text=value==ScanState.Ready?"점검 시작":"다시 점검";cancel.Enabled=value==ScanState.Scanning;
            save.Enabled=value==ScanState.Completed&&IsComplete;progressText.Text=message;
            summary.Text=value==ScanState.Completed&&IsComplete?ResultSummary():value==ScanState.Scanning?"점검 중 · 설정을 변경하지 않습니다.":value==ScanState.Cancelling?"중단 요청 중":value==ScanState.Cancelled?"중단됨 · 보고서 저장 불가":value==ScanState.Failed?"실패 · 보고서 저장 불가":"점검 전";
            UpdateNavigation();
        }
        string ResultSummary() {return String.Join("   ",Enum.GetValues(typeof(Verdict)).Cast<Verdict>().Select(v=>Labels.Of(v)+" "+audit.Findings.Count(f=>f.Status==v)));}
        internal void Navigate(int target)
        {
            if(target<0||target>3||worker.IsBusy||state==ScanState.Scanning||state==ScanState.Cancelling)return;
            if(target>=2&&(!IsComplete||state!=ScanState.Completed))return;
            step=target;for(int i=0;i<pages.Length;i++)pages[i].Visible=i==step;
            if(step==3)exportSummary.Text="저장 전 확인\r\n"+ResultSummary()+"\r\n수동 확인 미응답 "+answers.Count(x=>x.SelectedIndex==0)+"개 · 기관명·점검자·PC 사용자와 의견을 확인하십시오.";
            UpdateNavigation();
        }
        void UpdateNavigation()
        {
            string[] names={"점검 안내","자동 확인","수동 확인","정보 입력 및 출력"};
            steps.Text=String.Join("   →   ",names.Select((n,i)=>(i==step?"▶ ":"")+(i+1)+". "+n));
            bool busy=state==ScanState.Scanning||state==ScanState.Cancelling;
            previous.Enabled=step>0&&!busy;next.Visible=step<3;next.Enabled=!busy&&(step!=1||IsComplete&&state==ScanState.Completed);
            next.Text=step==0?"자동 확인으로":step==1?"수동 확인으로":"정보 입력 및 출력으로";
        }
        void UpdateManual() {manualProgress.Text="직원 수동 확인 · 응답 "+answers.Count(x=>x.SelectedIndex>0)+" / "+answers.Count+" · 미응답은 보고서에 그대로 기록됩니다.";}
        void RefreshGrid()
        {
            grid.Rows.Clear();if(audit==null)return;
            string selected=Convert.ToString(filter.SelectedItem);
            foreach(var f in audit.Findings)
            {
                if(selected!="전체"&&selected!=Labels.Of(f.Status))continue;
                int i=grid.Rows.Add(f.Id,f.Area,f.Name,Labels.Of(f.Status));grid.Rows[i].Tag=f;
                grid.Rows[i].Cells[3].Style.ForeColor=f.Status==Verdict.Weak?Color.Firebrick:f.Status==Verdict.Good?Color.DarkGreen:f.Status==Verdict.Unknown?Color.Purple:Color.FromArgb(110,78,0);
            }
            ShowFinding();
        }
        void ShowFinding()
        {
            if(grid.SelectedRows.Count==0){detail.Text="항목을 선택하십시오.";return;}
            var f=grid.SelectedRows[0].Tag as Finding;if(f==null)return;
            detail.Text=Guidance.Detail(f);
        }
        void SaveReport()
        {
            if(!IsComplete||step!=3||state!=ScanState.Completed)return;
            audit.Institution=institution.Text.Trim();audit.Inspector=inspector.Text.Trim();audit.PcUser=pcUser.Text.Trim();audit.Notes=notes.Text; audit.FollowUp=followup.Text;
            for(int i=0;i<answers.Count;i++)audit.Manual[i].Answer=answers[i].SelectedIndex==0?"미응답":Convert.ToString(answers[i].SelectedItem);
            if(MessageBox.Show(this,"수동 확인 미응답: "+answers.Count(x=>x.SelectedIndex==0)+"개\r\n미입력 정보: "+String.Join(", ",new[]{String.IsNullOrWhiteSpace(institution.Text)?"기관명":null,String.IsNullOrWhiteSpace(inspector.Text)?"점검자":null,String.IsNullOrWhiteSpace(pcUser.Text)?"PC 사용자":null}.Where(x=>x!=null))+"\r\n기관명: "+audit.Institution+"\r\n점검자: "+audit.Inspector+"\r\nPC 사용자: "+audit.PcUser+"\r\n\r\nPC 이름·계정·점검 결과를 다음 폴더에 HTML로 저장합니다.\r\n"+new ReportStore().OutputDirectory,"보고서 저장",MessageBoxButtons.OKCancel,MessageBoxIcon.Information)!=DialogResult.OK)return;
            try {string path=new ReportStore().Save(Report.Html(audit,false),audit.Info.ContainsKey("PC 이름")?audit.Info["PC 이름"]:"PC",audit.Started);MessageBox.Show(this,"보고서를 저장했습니다.\r\n\r\n"+path+"\r\n\r\n파일을 브라우저로 열고 Ctrl+P로 인쇄하거나 PDF로 저장하십시오.","저장 완료",MessageBoxButtons.OK,MessageBoxIcon.Information);}
            catch(Exception ex){MessageBox.Show(this,"저장하지 못했습니다. 폴더 접근 권한과 여유 공간을 확인한 후 재시도하십시오.\r\n\r\n"+(ex is System.IO.IOException?ex.Message:LocalSystem.Error(ex))+"\r\n\r\n불완전한 HTML 파일이 결과출력 안에 남을 수 있습니다. 재시도하면 새 이름으로 저장합니다.","저장 실패",MessageBoxButtons.OK,MessageBoxIcon.Error);}
        }
    }
}


