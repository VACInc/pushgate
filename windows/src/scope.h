#pragma once
#include <sddl.h>
namespace pg {
enum class AccountPolicy { Invalid, PasswordOnly, Approval };
inline bool UserSid(const std::wstring& text) {
    PSID sid=nullptr;
    if(!ConvertStringSidToSidW(text.c_str(),&sid))return false;
    bool ok=IsValidSid(sid)&&*GetSidSubAuthorityCount(sid)==5&&*GetSidSubAuthority(sid,0)==21;
    SID_IDENTIFIER_AUTHORITY nt=SECURITY_NT_AUTHORITY;
    ok=ok&&memcmp(GetSidIdentifierAuthority(sid),&nt,sizeof(nt))==0;
    LocalFree(sid);return ok;
}
inline AccountPolicy AccountScope(const std::wstring& candidate,const std::wstring& gated) {
    if(!UserSid(candidate)||!UserSid(gated))return AccountPolicy::Invalid;
    return candidate==gated?AccountPolicy::Approval:AccountPolicy::PasswordOnly;
}
inline AccountPolicy ReadAccountScope(const std::wstring& sid) {
    wchar_t value[256]{};DWORD bytes=sizeof(value);
    if(RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\PushGateWin",L"GatedAccountSid",RRF_RT_REG_SZ,nullptr,value,&bytes)!=ERROR_SUCCESS)return AccountPolicy::Invalid;
    return AccountScope(sid,value);
}
AccountPolicy ScopeForSid(const std::wstring&);
}
