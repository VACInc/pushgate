#pragma once
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#define SECURITY_WIN32
#include <ntsecapi.h>
#include <credentialprovider.h>
#include <string>
#include "scope.h"
namespace pg {
bool Enabled();
bool ValidatePassword(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION&, std::wstring&, std::wstring&);
bool Approve(const std::wstring&,const std::wstring&,const std::wstring&,IQueryContinueWithStatus*,volatile LONG*);
void Clear(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION&);
bool StringFromPacked(const BYTE*,DWORD,const UNICODE_STRING&,std::wstring&);
}
