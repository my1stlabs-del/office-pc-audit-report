using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace OfficePcAudit
{
    // No remote server argument is accepted by this boundary. Only fixed local WMI namespaces.
    internal static class LocalSystem
    {
        internal enum LoginKind { Local, Microsoft, Other }
        [StructLayout(LayoutKind.Sequential)] struct User24
        { public int InternetIdentity; public uint Flags; public IntPtr Provider,Principal,Sid; }
        [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern int NetUserGetInfo(string server,string user,uint level,out IntPtr buffer);
        [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WTSQuerySessionInformation(IntPtr server,int session,int info,out IntPtr buffer,out int bytes);
        [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr buffer);
        static string SessionText(int field)
        {
            IntPtr p=IntPtr.Zero;int bytes;
            try {
                using(var process=System.Diagnostics.Process.GetCurrentProcess())
                    if(!WTSQuerySessionInformation(IntPtr.Zero,process.SessionId,field,out p,out bytes))throw new Win32Exception(Marshal.GetLastWin32Error());
                return Marshal.PtrToStringUni(p)??"";
            } finally {if(p!=IntPtr.Zero)WTSFreeMemory(p);}
        }
        internal static LoginKind ClassifyLogin(bool internet,string provider)
        { return !internet?LoginKind.Local:String.Equals(provider,"MicrosoftAccount",StringComparison.OrdinalIgnoreCase)?LoginKind.Microsoft:LoginKind.Other; }
        public static LoginKind WindowsLoginKind()
        {
            // Session user, not the elevated process account or an Office account.
            string user=SessionText(5),domain=SessionText(7);
            if(String.IsNullOrEmpty(user))throw new InvalidOperationException("Windows 로그인 세션 사용자를 읽지 못했습니다.");
            if(!String.Equals(domain,Environment.MachineName,StringComparison.OrdinalIgnoreCase)&&!String.Equals(domain,"MicrosoftAccount",StringComparison.OrdinalIgnoreCase))return LoginKind.Other;
            IntPtr p=IntPtr.Zero;int code=NetUserGetInfo(null,user,24,out p);
            try {
                if(code!=0)throw new Win32Exception(code);
                if(p==IntPtr.Zero)throw new InvalidOperationException("로그인 계정 유형 반환값이 없습니다.");
                var x=(User24)Marshal.PtrToStructure(p,typeof(User24));
                return ClassifyLogin(x.InternetIdentity!=0,x.InternetIdentity!=0?Marshal.PtrToStringUni(x.Provider):null);
            } finally {if(p!=IntPtr.Zero)NetApiBufferFree(p);}
        }
        public const string Cim = @"root\cimv2", Defender = @"root\Microsoft\Windows\Defender",
            Security = @"root\SecurityCenter2", Encryption = @"root\cimv2\Security\MicrosoftVolumeEncryption",
            Tpm = @"root\cimv2\Security\MicrosoftTpm";
        public static List<Dictionary<string,object>> Query(string space, string query)
        {
            if (space != Cim && space != Defender && space != Security && space != Encryption && space != Tpm)
                throw new InvalidOperationException("허용되지 않은 조회 영역입니다.");
            if (!query.StartsWith("SELECT ",StringComparison.Ordinal) || query.Contains(";") || query.Contains("*"))
                throw new InvalidOperationException("허용되지 않은 조회입니다.");
            var scope = new ManagementScope(@"\\.\" + space, new ConnectionOptions { Timeout=TimeSpan.FromSeconds(8), EnablePrivileges=false, Authentication=AuthenticationLevel.PacketPrivacy, Impersonation=ImpersonationLevel.Impersonate });
            var options = new EnumerationOptions { ReturnImmediately=true, Rewindable=false, Timeout=TimeSpan.FromSeconds(8) };
            using (var search = new ManagementObjectSearcher(scope,new ObjectQuery(query),options))
            using (var rows = search.Get())
            {
                var result=new List<Dictionary<string,object>>();
                foreach (ManagementObject row in rows) using(row)
                {
                    var values = new Dictionary<string,object>(StringComparer.OrdinalIgnoreCase);
                    foreach (PropertyData p in row.Properties) values[p.Name]=p.Value;
                    result.Add(values);
                    if(result.Count > 1024) throw new InvalidOperationException("조회 결과 한도를 초과했습니다.");
                }
                return result;
            }
        }
        public static Dictionary<string,object> One(string space,string query)
        { var rows=Query(space,query); if(rows.Count==0) throw new InvalidOperationException("조회 가능한 항목이 없습니다."); return rows[0]; }
        // Only these three state-reading methods may cross the WMI method boundary.
        internal static bool AllowedStatusMethod(string space,string method)
        { return space==Tpm&&method=="IsReadyInformation" || space==Encryption&&(method=="GetProtectionStatus"||method=="GetConversionStatus"); }
        private static void ReadStatus(ManagementObject row,string space,string method,Dictionary<string,object> result)
        {
            if(!AllowedStatusMethod(space,method))throw new InvalidOperationException("허용되지 않은 상태 조회입니다.");
            if(row.Path==null||!row.Path.IsInstance)throw new InvalidOperationException(method+" 조회 실패: WMI 장치 경로가 없습니다.");
            using(var input=row.GetMethodParameters(method))
            {
                if(method=="GetConversionStatus")input["PrecisionFactor"]=0u;
                using(var output=row.InvokeMethod(method,input,new InvokeMethodOptions { Timeout=TimeSpan.FromSeconds(8) }))
                {
                    if(output==null||output["ReturnValue"]==null)throw new InvalidOperationException("상태 조회 반환값이 없습니다: "+method);
                    uint code=Convert.ToUInt32(output["ReturnValue"]);
                    if(code!=0)throw new InvalidOperationException(method+" 조회 실패: 0x"+code.ToString("X8"));
                    foreach(PropertyData p in output.Properties)if(p.Name!="ReturnValue")result[p.Name]=p.Value;
                }
            }
        }
        public static Dictionary<string,object> TpmStatus() { return VolumeOrTpmStatus(null); }
        public static Dictionary<string,object> EncryptionStatus(string drive)
        {
            if(String.IsNullOrEmpty(drive)||drive.Length!=2||drive[1]!=':'||!Char.IsLetter(drive[0]))throw new InvalidOperationException("드라이브 형식 오류");
            return VolumeOrTpmStatus(drive);
        }
        private static Dictionary<string,object> VolumeOrTpmStatus(string drive)
        {
            bool tpm=drive==null;string space=tpm?Tpm:Encryption;
            var scope=new ManagementScope(@"\\.\"+space,new ConnectionOptions { Timeout=TimeSpan.FromSeconds(8), EnablePrivileges=false, Authentication=AuthenticationLevel.PacketPrivacy, Impersonation=ImpersonationLevel.Impersonate });
            string query=tpm?"SELECT SpecVersion FROM Win32_Tpm":"SELECT DriveLetter FROM Win32_EncryptableVolume";
            // Projected SELECT results can omit their instance path. Methods need it.
            using(var search=new ManagementObjectSearcher(scope,new ObjectQuery(query),StatusQueryOptions()))
            using(var rows=search.Get())
            {
                foreach(ManagementObject row in rows)using(row)
                {
                    if(!tpm&&!String.Equals(Convert.ToString(row["DriveLetter"]),drive,StringComparison.OrdinalIgnoreCase))continue;
                    var result=new Dictionary<string,object>(StringComparer.OrdinalIgnoreCase);
                    if(tpm){result["SpecVersion"]=row["SpecVersion"];ReadStatus(row,space,"IsReadyInformation",result);}
                    else {ReadStatus(row,space,"GetProtectionStatus",result);ReadStatus(row,space,"GetConversionStatus",result);}
                    return result;
                }
            }
            return null;
        }
        internal static EnumerationOptions StatusQueryOptions()
        { return new EnumerationOptions { ReturnImmediately=true,Rewindable=false,EnsureLocatable=true,Timeout=TimeSpan.FromSeconds(8) }; }
        public static string Text(Dictionary<string,object> row,string key)
        { object v; return row.TryGetValue(key,out v) && v!=null ? Convert.ToString(v,CultureInfo.InvariantCulture) : "확인 불가"; }
        public static bool Bool(Dictionary<string,object> row,string key)
        { object v; if(!row.TryGetValue(key,out v) || v==null) throw new InvalidOperationException(key+" 값이 없습니다."); return Convert.ToBoolean(v,CultureInfo.InvariantCulture); }
        public static int Number(Dictionary<string,object> row,string key)
        { object v; if(!row.TryGetValue(key,out v) || v==null) throw new InvalidOperationException(key+" 값이 없습니다."); return Convert.ToInt32(v,CultureInfo.InvariantCulture); }
        public static object Reg(bool machine,string path,string name)
        {
            // OpenSubKey(false) is deliberately the only registry open mode in the product.
            using(var root=RegistryKey.OpenBaseKey(machine ? RegistryHive.LocalMachine : RegistryHive.CurrentUser,RegistryView.Registry64))
            using(var key=root.OpenSubKey(path,false))
                return key==null ? null : key.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames);
        }
        public static int? RegInt(bool machine,string path,string name)
        { object v=Reg(machine,path,name); if(v==null) return null; int n; if(!Int32.TryParse(Convert.ToString(v,CultureInfo.InvariantCulture),out n)) throw new InvalidOperationException("설정값 형식이 올바르지 않습니다: "+name); return n; }
        public static string RegText(bool machine,string path,string name)
        { return Convert.ToString(Reg(machine,path,name),CultureInfo.InvariantCulture); }
        public static int ScreenSetting(uint action)
        {
            // SPI_GETSCREENSAVEACTIVE / TIMEOUT / SECURE only. No SET actions.
            if(action!=16&&action!=14&&action!=0x76)throw new InvalidOperationException("허용되지 않은 화면 조회입니다.");
            int value;if(!SystemParametersInfo(action,0,out value,0))throw new Win32Exception(Marshal.GetLastWin32Error());return value;
        }
        [DllImport("user32.dll",SetLastError=true)] static extern bool SystemParametersInfo(uint action,uint parameter,out int value,uint flags);
        public static DateTime? Date(object v)
        {
            if(v==null) return null;
            if(v is DateTime) return (DateTime)v;
            string s=Convert.ToString(v,CultureInfo.InvariantCulture); DateTime d;
            try { if(s.Length>=21 && s[14]=='.') return ManagementDateTimeConverter.ToDateTime(s); } catch(ArgumentException) { }
            if(DateTime.TryParseExact(s,new[]{"M/d/yyyy","MM/dd/yyyy","yyyy-MM-dd","yyyyMMdd"},CultureInfo.InvariantCulture,DateTimeStyles.None,out d)) return d;
            return null;
        }
        public static string Error(Exception e)
        {
            if(e is UnauthorizedAccessException || (e is ManagementException && ((ManagementException)e).ErrorCode==ManagementStatus.AccessDenied))
                return "조회 권한이 부족합니다. 관리자 권한을 자동 요청하지 않았습니다.";
            if(e is QueryStillRunningException)return "이전 Windows 조회가 아직 종료되지 않아 새 조회를 시작하지 않았습니다. 잠시 후 다시 점검하거나 프로그램을 다시 실행하십시오.";
            if(e is TimeoutException) return "로컬 조회 제한시간을 초과했습니다.";
            if(e is ManagementException) return "Windows 조회 공급자 오류 ("+((ManagementException)e).ErrorCode+"). 기능 미지원 또는 서비스 상태를 확인하십시오.";
            if(e is Win32Exception) return "Windows 조회 오류 ("+((Win32Exception)e).NativeErrorCode+").";
            if(e is InvalidOperationException) return e.Message;
            return "조회 중 오류가 발생했습니다 ("+e.GetType().Name+").";
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFirmwareType(out uint firmware);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetDiskFreeSpaceEx(string directory,out ulong available,out ulong total,out ulong free);
        [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern int NetUserModalsGet(string server,uint level,out IntPtr buffer);
        [DllImport("netapi32.dll")] static extern int NetApiBufferFree(IntPtr buffer);
        [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern int NetLocalGroupGetMembers(string server,string group,uint level,out IntPtr buffer,uint length,out uint read,out uint total,ref UIntPtr resume);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupAccountSid(string system,byte[] sid,System.Text.StringBuilder name,ref uint nameLength,System.Text.StringBuilder domain,ref uint domainLength,out int use);
        [DllImport("wscapi.dll")] internal static extern int WscGetSecurityProviderHealth(uint providers,out int health);
        [StructLayout(LayoutKind.Sequential)] internal struct PasswordPolicy { public uint MinLength, MaxAge, MinAge, ForceLogoff, History; }
        [StructLayout(LayoutKind.Sequential)] internal struct LockoutPolicy { public uint Duration, Window, Threshold; }
        public static T Policy<T>(uint level) where T:struct
        {
            IntPtr p; int code=NetUserModalsGet(null,level,out p);
            try { if(code!=0) throw new Win32Exception(code); return (T)Marshal.PtrToStructure(p,typeof(T)); }
            finally { if(p!=IntPtr.Zero) NetApiBufferFree(p); }
        }
        public static List<string> AdministratorSids()
        {
            var sid=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null); var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
            uint nl=256,dl=256;int use;var name=new System.Text.StringBuilder(256);var domain=new System.Text.StringBuilder(256);
            // This SID is the built-in local alias; no arbitrary SID/name resolution is performed.
            if(!LookupAccountSid(null,bytes,name,ref nl,domain,ref dl,out use)) throw new Win32Exception(Marshal.GetLastWin32Error());
            UIntPtr resume=UIntPtr.Zero; var found=new List<string>();uint read,total;IntPtr buffer;
            int code=NetLocalGroupGetMembers(null,name.ToString(),0,out buffer,UInt32.MaxValue,out read,out total,ref resume);
            try {
                if(code!=0) throw new Win32Exception(code);
                for(int i=0;i<(int)read;i++) found.Add(new SecurityIdentifier(Marshal.ReadIntPtr(buffer,i*IntPtr.Size)).Value);
            } finally { if(buffer!=IntPtr.Zero) NetApiBufferFree(buffer); }
            return found;
        }
        public static string Firmware()
        { uint type; if(!GetFirmwareType(out type)) throw new Win32Exception(Marshal.GetLastWin32Error()); return type==2?"UEFI":type==1?"BIOS":"확인 불가"; }
        public static string Disk(string drive)
        { ulong a,t,f;if(!GetDiskFreeSpaceEx(drive+@"\",out a,out t,out f))throw new Win32Exception(Marshal.GetLastWin32Error());return drive+" 총 "+(t/1073741824d).ToString("N1")+" GB / 여유 "+(f/1073741824d).ToString("N1")+" GB"; }
    }
}

