using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace OfficePcAudit
{
    // All product file writes live here. No caller can supply an output directory or filename.
    public sealed class ReportStore
    {
        private readonly string applicationDirectory;
        public string OutputDirectory { get { return Path.Combine(applicationDirectory,"결과출력"); } }
        public ReportStore() : this(AppDomain.CurrentDomain.BaseDirectory) { }
        internal ReportStore(string appDirectory) { applicationDirectory=Path.GetFullPath(appDirectory).TrimEnd(Path.DirectorySeparatorChar); }
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInfoNative info);
        [StructLayout(LayoutKind.Sequential)] struct FileInfoNative
        { public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
        static SafeFileHandle LockDirectory(string path)
        {
            // OPEN_REPARSE_POINT + BACKUP_SEMANTICS; deliberately omit FILE_SHARE_DELETE.
            var handle=CreateFile(path,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
            if(handle.IsInvalid){handle.Dispose();throw new Win32Exception(Marshal.GetLastWin32Error());}
            FileInfoNative info;
            if(!GetFileInformationByHandle(handle,out info)){handle.Dispose();throw new IOException("저장 폴더를 검사하지 못했습니다.");}
            if((info.Attributes&0x400)!=0 || (info.Attributes&0x10)==0){handle.Dispose();throw new IOException("연결 폴더·재분석 지점에는 저장할 수 없습니다. 일반 로컬 폴더에 프로그램을 압축 해제하십시오.");}
            return handle;
        }
        internal static string HostToken(string host)
        {
            var b=new StringBuilder();foreach(char c in host??"PC")if(Char.IsLetterOrDigit(c)||c=='-'||c=='_')b.Append(c);
            return b.Length==0?"PC":b.ToString(0,Math.Min(b.Length,48));
        }
        public string Save(string html,string host,DateTime date)
        {
            if(applicationDirectory.StartsWith(@"\\",StringComparison.Ordinal) || applicationDirectory.Length<3 || applicationDirectory[1]!=':')
                throw new IOException("네트워크 경로에는 저장하지 않습니다. 로컬 디스크에서 실행하십시오.");
            string root=Path.GetPathRoot(applicationDirectory);var drive=new DriveInfo(root);
            if(drive.DriveType!=DriveType.Fixed && drive.DriveType!=DriveType.Removable)throw new IOException("일반 로컬 디스크 또는 USB 저장장치에서 실행하십시오.");
            var locks=new List<SafeFileHandle>();
            try
            {
                locks.Add(LockDirectory(root));string current=root;
                foreach(string component in applicationDirectory.Substring(root.Length).Split(new[]{Path.DirectorySeparatorChar},StringSplitOptions.RemoveEmptyEntries))
                {current=Path.Combine(current,component);locks.Add(LockDirectory(current));}
                // The entire ancestor chain is locked against rename/delete before creating the only allowed directory.
                if(!Directory.Exists(OutputDirectory))Directory.CreateDirectory(OutputDirectory);
                locks.Add(LockDirectory(OutputDirectory));
                string filename="PC보안점검_"+HostToken(host)+"_"+date.ToString("yyyyMMdd_HHmmss")+"_"+Guid.NewGuid().ToString("N").Substring(0,8)+".html";
                string path=Path.Combine(OutputDirectory,filename);
                if(!String.Equals(Path.GetDirectoryName(Path.GetFullPath(path)),OutputDirectory,StringComparison.OrdinalIgnoreCase))throw new IOException("허용된 저장 경로를 벗어났습니다.");
                // CreateNew fails on any existing file/link. Existing reports are never overwritten.
                using(var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
                using(var writer=new StreamWriter(stream,new UTF8Encoding(false)))writer.Write(html);
                return path;
            }
            finally {for(int i=locks.Count-1;i>=0;i--)locks[i].Dispose();}
        }
    }
}
