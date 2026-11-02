#include "../src/gate.h"
#include <cstdio>
#include <cstring>
int main(){
 int failed=0;auto check=[&](bool b,const char* n){std::printf("%s %s\n",b?"PASS":"FAIL",n);if(!b)++failed;};
 BYTE bytes[sizeof(KERB_INTERACTIVE_UNLOCK_LOGON)+16]{};
 const DWORD off=sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);memcpy(bytes+off,L"test",8);
 UNICODE_STRING s{};s.Buffer=(PWSTR)(ULONG_PTR)off;s.Length=s.MaximumLength=8;std::wstring out;
 check(pg::StringFromPacked(bytes,sizeof(bytes),s,out)&&out==L"test","relative serialized string accepted");
 s.Buffer=(PWSTR)1;check(!pg::StringFromPacked(bytes,sizeof(bytes),s,out),"pointer into header refused");
 s.Buffer=(PWSTR)(ULONG_PTR)(sizeof(bytes)-2);check(!pg::StringFromPacked(bytes,sizeof(bytes),s,out),"out of bounds refused");
 s.Buffer=(PWSTR)(ULONG_PTR)off;s.Length=7;check(!pg::StringFromPacked(bytes,sizeof(bytes),s,out),"odd byte length refused");
 s.Length=8;bytes[off+2]=0;bytes[off+3]=0;check(!pg::StringFromPacked(bytes,sizeof(bytes),s,out),"embedded null refused");
 s.Length=0;s.Buffer=nullptr;check(pg::StringFromPacked(bytes,sizeof(bytes),s,out)&&out.empty(),"empty serialized domain accepted without dereference");
 CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION c{};std::wstring user,sid;
 check(!pg::ValidatePassword(c,user,sid),"missing serialized credentials refused");
 c.rgbSerialization=bytes;c.cbSerialization=sizeof(bytes);check(!pg::ValidatePassword(c,user,sid),"unknown logon type refused before credential use");
 return failed?1:0;
}
