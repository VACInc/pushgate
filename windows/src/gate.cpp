#include "gate.h"
#include <aclapi.h>
#include <sddl.h>
#include <wincred.h>
#include <wtsapi32.h>
#include <vector>
namespace pg {
void Clear(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION& s) {
    if(s.rgbSerialization){SecureZeroMemory(s.rgbSerialization,s.cbSerialization);CoTaskMemFree(s.rgbSerialization);}
    ZeroMemory(&s,sizeof(s));
}
AccountPolicy ScopeForSid(const std::wstring& sid){return ReadAccountScope(sid);}
bool Enabled(){DWORD v=0,n=sizeof(v);return RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\PushGateWin",L"FilterEnabled",RRF_RT_REG_DWORD,nullptr,&v,&n)==ERROR_SUCCESS && v==1;}
bool StringFromPacked(const BYTE* b,DWORD n,const UNICODE_STRING& s,std::wstring& out){
    if(s.Length==0){out.clear();return true;}
    ULONG_PTR off=(ULONG_PTR)s.Buffer;
    if(s.Length%2 || s.Length>2048 || off<sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) || off>n || s.Length>n-off)return false;
    out.assign((const wchar_t*)(b+off),s.Length/2);
    return out.find(L'\0')==std::wstring::npos;
}
bool ValidatePassword(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION& s,std::wstring& user,std::wstring& sid){
    if(!s.rgbSerialization || s.cbSerialization<sizeof(KERB_INTERACTIVE_UNLOCK_LOGON))return false;
    const auto* k=(const KERB_INTERACTIVE_UNLOCK_LOGON*)s.rgbSerialization;
    if(k->Logon.MessageType!=KerbInteractiveLogon && k->Logon.MessageType!=KerbWorkstationUnlockLogon)return false;
    std::wstring domain,pw;
    if(!StringFromPacked(s.rgbSerialization,s.cbSerialization,k->Logon.LogonDomainName,domain)||
       !StringFromPacked(s.rgbSerialization,s.cbSerialization,k->Logon.UserName,user)||
       !StringFromPacked(s.rgbSerialization,s.cbSerialization,k->Logon.Password,pw))return false;
    CRED_PROTECTION_TYPE type=CredUnprotected;
    if(!pw.empty()&&!CredIsProtectedW(pw.data(),&type)){SecureZeroMemory(pw.data(),pw.size()*2);return false;}
    if(type!=CredUnprotected){
        DWORD size=0;CredUnprotectW(FALSE,pw.data(),(DWORD)pw.size()+1,nullptr,&size);
        if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER || size>2048){SecureZeroMemory(pw.data(),pw.size()*2);return false;}
        std::vector<wchar_t> plain(size);
        bool ok=CredUnprotectW(FALSE,pw.data(),(DWORD)pw.size()+1,plain.data(),&size);
        SecureZeroMemory(pw.data(),pw.size()*2);
        if(ok)pw.assign(plain.data());
        SecureZeroMemory(plain.data(),plain.size()*2);
        if(!ok)return false;
    }
    HANDLE token=nullptr;
    BOOL ok=LogonUserW(user.c_str(),domain.empty()?nullptr:domain.c_str(),pw.c_str(),LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&token);
    DWORD error=ok?ERROR_SUCCESS:GetLastError();
    SecureZeroMemory(pw.data(),pw.size()*2);
    if(!ok){
        // Windows reports these statuses only after checking the password.
        // Gate the original serialization, then let Winlogon run its normal
        // change-password flow rather than trapping the owner at sign-in.
        if(error!=ERROR_PASSWORD_EXPIRED && error!=ERROR_PASSWORD_MUST_CHANGE)return false;
        std::wstring account=domain.empty()?user:domain+L"\\"+user;
        DWORD bytes=0,domainChars=0;SID_NAME_USE kind;
        LookupAccountNameW(nullptr,account.c_str(),nullptr,&bytes,nullptr,&domainChars,&kind);
        if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER||bytes>65536||domainChars>1024)return false;
        std::vector<BYTE> accountSid(bytes);std::vector<wchar_t> resolved(domainChars);LPWSTR text=nullptr;
        if(!LookupAccountNameW(nullptr,account.c_str(),accountSid.data(),&bytes,resolved.data(),&domainChars,&kind)||kind!=SidTypeUser)return false;
        if(!ConvertSidToStringSidW(accountSid.data(),&text))return false;
        sid=text;LocalFree(text);return true;
    }
    DWORD n=0;GetTokenInformation(token,TokenUser,nullptr,0,&n);
    std::vector<BYTE> info(n);LPWSTR text=nullptr;
    ok=GetTokenInformation(token,TokenUser,info.data(),n,&n) && ConvertSidToStringSidW(((TOKEN_USER*)info.data())->User.Sid,&text);
    if(ok){sid=text;LocalFree(text);}CloseHandle(token);return ok;
}
static bool Trusted(const wchar_t* path){
    PACL dacl=nullptr;PSID owner=nullptr;PSECURITY_DESCRIPTOR sd=nullptr;
    if(GetNamedSecurityInfoW(path,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION,&owner,nullptr,&dacl,nullptr,&sd))return false;
    auto trusted=[](PSID s){return IsWellKnownSid(s,WinLocalSystemSid)||IsWellKnownSid(s,WinBuiltinAdministratorsSid);};
    bool ok=owner && trusted(owner) && dacl;SECURITY_DESCRIPTOR_CONTROL control=0;DWORD rev=0;
    if(ok && (!GetSecurityDescriptorControl(sd,&control,&rev)||!(control&SE_DACL_PROTECTED)))ok=false;
    const ACCESS_MASK writes=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_DELETE_CHILD|FILE_WRITE_ATTRIBUTES|DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL|MAXIMUM_ALLOWED;
    for(DWORD i=0;ok && i<dacl->AceCount;i++){ACE_HEADER* h=nullptr;if(!GetAce(dacl,i,(void**)&h)){ok=false;break;}if(h->AceType==ACCESS_DENIED_ACE_TYPE)continue;
        if(h->AceType!=ACCESS_ALLOWED_ACE_TYPE){ok=false;break;}auto* a=(ACCESS_ALLOWED_ACE*)h;if((a->Mask&writes)&&!trusted((PSID)&a->SidStart))ok=false;}
    LocalFree(sd);DWORD attr=GetFileAttributesW(path);return ok && attr!=INVALID_FILE_ATTRIBUTES && !(attr&FILE_ATTRIBUTE_REPARSE_POINT);
}
static std::string Json(const std::wstring& w){
    std::string s="\"";for(wchar_t c:w){if(c<32 || c>126)return "";if(c=='"'||c=='\\')s+='\\';s+=(char)c;}return s+'"';
}
// GetSerialization is synchronous for the password provider. Keep its waiting
// and cancel UI on a separate secure-desktop thread, not on the blocked caller.
class WaitWindow {
    volatile LONG* cancel;HANDLE ready=nullptr,thread=nullptr;HWND window=nullptr;
    static LRESULT CALLBACK Proc(HWND w,UINT m,WPARAM p,LPARAM l){
        auto* self=(WaitWindow*)GetWindowLongPtrW(w,GWLP_USERDATA);
        if(m==WM_NCCREATE){self=(WaitWindow*)((CREATESTRUCTW*)l)->lpCreateParams;SetWindowLongPtrW(w,GWLP_USERDATA,(LONG_PTR)self);}
        if(self && (m==WM_CLOSE || (m==WM_COMMAND && LOWORD(p)==IDCANCEL))){
            InterlockedExchange(self->cancel,1);SetWindowTextW(w,L"Canceling sign-in");EnableWindow(GetDlgItem(w,IDCANCEL),FALSE);return 0;
        }
        if(m==WM_APP){DestroyWindow(w);return 0;}
        if(m==WM_DESTROY){PostQuitMessage(0);return 0;}
        return DefWindowProcW(w,m,p,l);
    }
    static DWORD WINAPI Run(void* argument){
        auto* self=(WaitWindow*)argument;HINSTANCE module=nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCWSTR)&Run,&module);
        wchar_t name[64];swprintf(name,64,L"PushGateWait%lu",GetCurrentThreadId());
        WNDCLASSW cls{};cls.lpfnWndProc=Proc;cls.hInstance=module;cls.lpszClassName=name;cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);cls.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
        if(!RegisterClassW(&cls)){SetEvent(self->ready);return 1;}
        self->window=CreateWindowExW(WS_EX_TOPMOST|WS_EX_TOOLWINDOW,name,L"Waiting for approval",WS_CAPTION|WS_SYSMENU|WS_VISIBLE,
            (GetSystemMetrics(SM_CXSCREEN)-440)/2,(GetSystemMetrics(SM_CYSCREEN)-180)/2,440,180,nullptr,nullptr,module,self);
        if(self->window){
            CreateWindowW(L"STATIC",L"PushGate is waiting for sign-in approval.\nApprove or deny on your phone.",WS_CHILD|WS_VISIBLE,20,20,390,55,self->window,nullptr,module,nullptr);
            CreateWindowW(L"BUTTON",L"Cancel",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,160,90,100,30,self->window,(HMENU)IDCANCEL,module,nullptr);
            UpdateWindow(self->window);
        }
        SetEvent(self->ready);
        if(self->window){MSG message;while(GetMessageW(&message,nullptr,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}}
        UnregisterClassW(name,module);return 0;
    }
public:
    explicit WaitWindow(volatile LONG* c,bool show):cancel(c){
        if(!show)return;ready=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if(ready){thread=CreateThread(nullptr,0,Run,this,0,nullptr);if(thread)WaitForSingleObject(ready,INFINITE);}
    }
    bool Visible()const{return window!=nullptr;}
    ~WaitWindow(){if(thread){if(window)PostMessageW(window,WM_APP,0,0);WaitForSingleObject(thread,INFINITE);CloseHandle(thread);}if(ready)CloseHandle(ready);}
};
bool Approve(const std::wstring& user,const std::wstring& sid,const std::wstring& code,IQueryContinueWithStatus* q,volatile LONG* cancel){
    const wchar_t* base=L"C:\\ProgramData\\PushGateWin";
    const wchar_t* gate=L"C:\\Program Files\\PushGateWin\\Gate.ps1";
    if(!Trusted(base)||!Trusted(L"C:\\Program Files\\PushGateWin")||!Trusted(gate)||!Trusted(L"C:\\Program Files\\PushGateWin\\Client.psm1")||!Trusted(L"C:\\ProgramData\\PushGateWin\\client.env")||!Trusted(L"C:\\ProgramData\\PushGateWin\\recovery.json"))return false;
    WaitWindow waiting(cancel,!q);if(!q && !waiting.Visible())return false;
    DWORD session=0;if(!ProcessIdToSessionId(GetCurrentProcessId(),&session))return false;
    std::wstring source=L"console";LPWSTR proto=nullptr;DWORD count=0;
    if(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSClientProtocolType,&proto,&count)){
        if(count>=2 && *(USHORT*)proto!=0){source=L"RDP unknown";LPWSTR host=nullptr;DWORD bytes=0;
            if(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSClientName,&host,&bytes)){if(host && *host)source=L"RDP "+std::wstring(host);WTSFreeMemory(host);}}
        WTSFreeMemory(proto);
    }
    const auto ju=Json(user),js=Json(sid),jc=Json(code),jr=Json(source);
    if(ju.empty()||js.empty()||jc.empty()||jr.empty())return false;
    std::string input="{\"user\":"+ju+",\"sid\":"+js+",\"source\":"+jr+",\"code\":"+jc+"}\n";
    HANDLE inRead=nullptr,inWrite=nullptr,outRead=nullptr,outWrite=nullptr;
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
    if(!CreatePipe(&inRead,&inWrite,&sa,0))return false;
    if(!CreatePipe(&outRead,&outWrite,&sa,0)){CloseHandle(inRead);CloseHandle(inWrite);return false;}
    SetHandleInformation(inWrite,HANDLE_FLAG_INHERIT,0);SetHandleInformation(outRead,HANDLE_FLAG_INHERIT,0);
    wchar_t system[MAX_PATH];if(!GetSystemDirectoryW(system,MAX_PATH)){CloseHandle(inRead);CloseHandle(inWrite);CloseHandle(outRead);CloseHandle(outWrite);return false;}
    std::wstring exe=std::wstring(system)+L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    std::wstring cmd=L"\""+exe+L"\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+gate+L"\"";
    STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdInput=inRead;si.StartupInfo.hStdOutput=outWrite;si.StartupInfo.hStdError=outWrite;
    SIZE_T attrSize=0;InitializeProcThreadAttributeList(nullptr,1,0,&attrSize);
    std::vector<BYTE> attr(attrSize);si.lpAttributeList=(LPPROC_THREAD_ATTRIBUTE_LIST)attr.data();
    HANDLE handles[]={inRead,outWrite};
    BOOL attributes=InitializeProcThreadAttributeList(si.lpAttributeList,1,0,&attrSize);
    if(attributes)attributes=UpdateProcThreadAttribute(si.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,handles,sizeof(handles),nullptr,nullptr);
    PROCESS_INFORMATION pi{};
    BOOL started=attributes&&CreateProcessW(exe.c_str(),cmd.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi);
    if(attributes)DeleteProcThreadAttributeList(si.lpAttributeList);
    CloseHandle(inRead);CloseHandle(outWrite);
    if(!started){CloseHandle(inWrite);CloseHandle(outRead);SecureZeroMemory(input.data(),input.size());return false;}
    CloseHandle(pi.hThread);DWORD wrote=0;bool ok=WriteFile(inWrite,input.data(),(DWORD)input.size(),&wrote,nullptr)&&wrote==input.size();CloseHandle(inWrite);SecureZeroMemory(input.data(),input.size());
    ULONGLONG deadline=GetTickCount64()+75000;std::string output;bool done=false;
    if(q)q->SetStatusMessage(L"Waiting for PushGate approval. Approve or deny on your phone.");
    while(ok && GetTickCount64()<deadline){
        if(InterlockedCompareExchange(cancel,0,0) || (q && q->QueryContinue()!=S_OK)){ok=false;break;}
        DWORD available=0;if(!PeekNamedPipe(outRead,nullptr,0,nullptr,&available,nullptr)){if(GetLastError()!=ERROR_BROKEN_PIPE)ok=false;}
        if(available){char buf[256];DWORD got=0;if(available>1024-output.size()||!ReadFile(outRead,buf,(DWORD)sizeof(buf),&got,nullptr)){ok=false;break;}output.append(buf,got);}
        if(WaitForSingleObject(pi.hProcess,100)==WAIT_OBJECT_0){done=true;break;}
    }
    // Only this helper process belongs to this attempt. Cancellation never
    // kills LogonUI, SSH, or another process's work.
    if(!done){TerminateProcess(pi.hProcess,1);WaitForSingleObject(pi.hProcess,5000);ok=false;}
    DWORD exitCode=1;GetExitCodeProcess(pi.hProcess,&exitCode);
    if(ok){char buf[256];DWORD got=0;while(ReadFile(outRead,buf,sizeof(buf),&got,nullptr)&&got){output.append(buf,got);if(output.size()>1024){ok=false;break;}}}
    CloseHandle(pi.hProcess);CloseHandle(outRead);
    return ok && exitCode==0 && (output=="APPROVED\r\n"||output=="APPROVED\n");
}
}
