#include "../src/gate.h"
#include <cstdio>
int main(){int errors=0;auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);errors+=!ok;};
const std::wstring gated=L"S-1-5-21-1-2-3-1001",other=L"S-1-5-21-1-2-3-1002";
check(pg::AccountScope(gated,gated)==pg::AccountPolicy::Approval,"Gated account SID requires approval");
check(pg::AccountScope(other,gated)==pg::AccountPolicy::PasswordOnly,"Other account SID uses normal password");
check(pg::AccountScope(gated,L"")==pg::AccountPolicy::Invalid,"missing scope fails closed");
check(pg::AccountScope(L"not-a-sid",gated)==pg::AccountPolicy::Invalid,"malformed user fails closed");
check(pg::AccountScope(other,L"S-1-5-18")==pg::AccountPolicy::Invalid,"system SID cannot configure account scope");
check(pg::AccountScope(gated,other)==pg::AccountPolicy::PasswordOnly,"policy compares account SID not supplied name");return errors?1:0;}
