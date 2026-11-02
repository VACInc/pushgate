// Uses only a new disposable local account in the isolated Windows guest.
#include "../src/gate.h"
#include <lm.h>
#include <vector>
#include <cstdio>

static bool Validate(const std::wstring& machine,const std::wstring& password){
    const std::wstring name=L"pgexp";
    std::vector<BYTE> data(sizeof(KERB_INTERACTIVE_UNLOCK_LOGON)+(machine.size()+name.size()+password.size())*2);
    auto* k=(KERB_INTERACTIVE_UNLOCK_LOGON*)data.data();k->Logon.MessageType=KerbInteractiveLogon;
    size_t offset=sizeof(*k);
    auto put=[&](UNICODE_STRING& field,const std::wstring& value){field.Length=field.MaximumLength=(USHORT)(value.size()*2);field.Buffer=(PWSTR)offset;memcpy(data.data()+offset,value.data(),field.Length);offset+=field.Length;};
    put(k->Logon.LogonDomainName,machine);put(k->Logon.UserName,name);put(k->Logon.Password,password);
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION s{};s.rgbSerialization=data.data();s.cbSerialization=(DWORD)data.size();
    std::wstring user,sid;bool ok=pg::ValidatePassword(s,user,sid);SecureZeroMemory(data.data(),data.size());
    return ok&&user==name&&sid.find(L"S-1-5-21-")==0;
}
int main(){
    wchar_t machine[MAX_COMPUTERNAME_LENGTH+1];DWORD size=MAX_COMPUTERNAME_LENGTH+1;
    if(!GetComputerNameW(machine,&size)||_wcsicmp(machine,L"pgwin")){puts("FAIL isolated guest required");return 1;}
    LPBYTE existing=nullptr;NET_API_STATUS result=NetUserGetInfo(nullptr,L"pgexp",1,&existing);
    if(existing)NetApiBufferFree(existing);
    if(result!=NERR_UserNotFound){puts("FAIL refusing existing test account");return 1;}
    GUID random{};if(FAILED(CoCreateGuid(&random)))return 1;wchar_t guid[40];StringFromGUID2(random,guid,40);
    std::wstring candidate=std::wstring(L"aA1!")+guid;
    USER_INFO_1 account{};
    account.usri1_name=(LPWSTR)L"pgexp";
    auto value=candidate.data();
    account.usri1_password=value;
    account.usri1_priv=USER_PRIV_USER;
    account.usri1_flags=UF_SCRIPT|UF_NORMAL_ACCOUNT;
    DWORD parameter=0;result=NetUserAdd(nullptr,1,(LPBYTE)&account,&parameter);
    if(result){printf("FAIL create disposable account status=%lu\n",result);return 1;}
    int failures=0;auto check=[&](bool ok,const char* message){printf("%s %s\n",ok?"PASS":"FAIL",message);if(!ok)++failures;};
    check(Validate(machine,candidate),"ordinary valid password accepted");
    USER_INFO_4* info=nullptr;result=NetUserGetInfo(nullptr,L"pgexp",4,(LPBYTE*)&info);
    if(!result){info->usri4_password_expired=1;result=NetUserSetInfo(nullptr,L"pgexp",4,(LPBYTE)info,&parameter);NetApiBufferFree(info);}
    check(result==NERR_Success,"disposable password marked for change");
    HANDLE token=nullptr;BOOL ok=LogonUserW(L"pgexp",machine,(candidate+L"wrong").c_str(),LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&token);DWORD wrong=ok?0:GetLastError();if(token)CloseHandle(token);
    token=nullptr;ok=LogonUserW(L"pgexp",machine,candidate.c_str(),LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&token);DWORD correct=ok?0:GetLastError();if(token)CloseHandle(token);
    printf("Windows expired-account status: wrong=%lu correct=%lu\n",wrong,correct);
    check(wrong==ERROR_LOGON_FAILURE,"expired account still rejects wrong password");
    check(correct==ERROR_PASSWORD_EXPIRED||correct==ERROR_PASSWORD_MUST_CHANGE,"correct expired password has distinct Windows status");
    check(!Validate(machine,candidate+L"wrong"),"gate rejects incorrect expired password");
    check(Validate(machine,candidate),"gate preserves verified password-change flow");
    SecureZeroMemory(candidate.data(),candidate.size()*2);
    check(NetUserDel(nullptr,L"pgexp")==NERR_Success,"only newly created disposable account removed");
    return failures?1:0;
}
