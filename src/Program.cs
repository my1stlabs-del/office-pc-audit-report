using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
[assembly:System.Reflection.AssemblyTitle("업무용 PC 보안점검 도구")]
[assembly:System.Reflection.AssemblyVersion("1.0.0.0")]
namespace OfficePcAudit
{
    internal static class Program
    {
        [DllImport("user32.dll")]static extern bool SetProcessDPIAware();
        [STAThread] static void Main()
        {
            if(!Environment.Is64BitOperatingSystem){MessageBox.Show("Windows 10/11 x64 환경에서 실행하십시오.");return;}
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException+=(s,e)=>MessageBox.Show("화면 처리 중 오류가 발생했습니다. 현재 작업을 다시 시도하십시오.\n"+e.Exception.GetType().Name,"오류",MessageBoxButtons.OK,MessageBoxIcon.Error);
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new MainForm());
        }
    }
}





