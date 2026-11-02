// In-process COM protocol tests. No network, real passwords, registry or notifier.
#include <cstdio>
#include <cstdlib>
#include "../src/provider.cpp"
static bool enable=false, valid=false, permit=false, liveScope=false;
static std::wstring accountSid=L"S-1-5-21-1-2-3-4";
static pg::AccountPolicy scope=pg::AccountPolicy::Approval;
static int gateCalls=0,failures=0;static Credential* interleaved=nullptr;
namespace pg {
bool Enabled(){return enable;}
AccountPolicy ScopeForSid(const std::wstring& sid){return liveScope?ReadAccountScope(sid):scope;}
bool ValidatePassword(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION&,std::wstring& u,std::wstring& s){u=L"fixture";s=accountSid;return valid;}
bool Approve(const std::wstring&,const std::wstring&,const std::wstring&,IQueryContinueWithStatus*,volatile LONG*){++gateCalls;if(interleaved)interleaved->SetStringValue(0,L"changed during wait");return permit;}
void Clear(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION& s){if(s.rgbSerialization){SecureZeroMemory(s.rgbSerialization,s.cbSerialization);CoTaskMemFree(s.rgbSerialization);}ZeroMemory(&s,sizeof(s));}
}
static void Check(bool ok,const char* label){if(!ok){++failures;std::printf("FAIL %s\n",label);}else std::printf("PASS %s\n",label);}
class Fake final:public ICredentialProviderCredential2{
 LONG refs=1;
public:
 REFCOUNT
 HRESULT STDMETHODCALLTYPE QueryInterface(REFIID r,void** p) override{if(!p)return E_POINTER;*p=nullptr;if(r!=IID_IUnknown&&r!=IID_ICredentialProviderCredential&&r!=IID_ICredentialProviderCredential2)return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
 HRESULT STDMETHODCALLTYPE GetUserSid(LPWSTR* out) override{return Copy(accountSid.c_str(),out);}
 HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderCredentialEvents*) override{return S_OK;}
 HRESULT STDMETHODCALLTYPE UnAdvise() override{return S_OK;}
 HRESULT STDMETHODCALLTYPE SetSelected(BOOL* a) override{*a=FALSE;return S_OK;}
 HRESULT STDMETHODCALLTYPE SetDeselected() override{return S_OK;}
 HRESULT STDMETHODCALLTYPE GetFieldState(DWORD,CREDENTIAL_PROVIDER_FIELD_STATE*,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE*) override{return E_NOTIMPL;}
 HRESULT STDMETHODCALLTYPE GetStringValue(DWORD,LPWSTR*) override{return E_NOTIMPL;}
 HRESULT STDMETHODCALLTYPE GetBitmapValue(DWORD,HBITMAP*) override{return E_NOTIMPL;}
 HRESULT STDMETHODCALLTYPE GetCheckboxValue(DWORD,BOOL*,LPWSTR*) override{return E_NOTIMPL;}
 HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(DWORD,DWORD*) override{return E_NOTIMPL;}
 HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(DWORD,DWORD*,DWORD*) override{return E_NOTIMPL;}
 HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(DWORD,DWORD,LPWSTR*) override{return E_NOTIMPL;}
 HRESULT STDMETHODCALLTYPE SetStringValue(DWORD,LPCWSTR) override{return S_OK;}
 HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD,BOOL) override{return S_OK;}
 HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD,DWORD) override{return S_OK;}
 HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD) override{return S_OK;}
 HRESULT STDMETHODCALLTYPE GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* r,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* s,LPWSTR* t,CREDENTIAL_PROVIDER_STATUS_ICON* i) override{*r=CPGSR_RETURN_CREDENTIAL_FINISHED;ZeroMemory(s,sizeof(*s));s->rgbSerialization=(BYTE*)CoTaskMemAlloc(8);s->cbSerialization=8;memset(s->rgbSerialization,42,8);*t=nullptr;*i=CPSI_NONE;return S_OK;}
 HRESULT STDMETHODCALLTYPE ReportResult(NTSTATUS,NTSTATUS,LPWSTR*,CREDENTIAL_PROVIDER_STATUS_ICON*) override{return S_OK;}
};
static bool Releases(Credential* c){CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE r;CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION s{};LPWSTR t=nullptr;CREDENTIAL_PROVIDER_STATUS_ICON i;HRESULT h=c->GetSerialization(&r,&s,&t,&i);bool ok=h==S_OK && r==CPGSR_RETURN_CREDENTIAL_FINISHED && s.rgbSerialization;CoTaskMemFree(t);pg::Clear(s);return ok;}
int wmain(int argc,wchar_t** argv){
 if(argc==4 && std::wstring(argv[1])==L"--live-scope"){
  liveScope=true;accountSid=argv[2];valid=true;permit=false;auto* fake=new Fake();auto* credential=new Credential(fake,3,CLSID_PgPassword);fake->Release();
  Check(!Releases(credential)&&gateCalls==1,"live Gated account SID denial blocks credentials");
  permit=true;Check(Releases(credential)&&gateCalls==2,"live Gated account SID approval releases credentials");
  accountSid=argv[3];permit=false;int before=gateCalls;
  Check(Releases(credential)&&gateCalls==before,"live Other account SID submits password without an approval call");
  CREDENTIAL_PROVIDER_FIELD_STATE fs;CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE fi;
  credential->GetFieldState(3,&fs,&fi);Check(fs==CPFS_HIDDEN,"live Other account tile hides recovery field");
  valid=false;Check(!Releases(credential)&&gateCalls==before,"live Other account still requires accepted password");
  credential->Release();return failures?1:0;
 }
 auto* f=new Fake();auto* c=new Credential(f,3,CLSID_PgPassword);f->Release();
 Check(!Releases(c),"no credentials before approval");
 Check(FAILED(c->Connect(nullptr))&&gateCalls==0,"bad password never sends a push");
 valid=true;permit=false;int deniedCalls=gateCalls;Check(FAILED(c->Connect(nullptr))&&!Releases(c),"denial blocks credentials");
 Check(gateCalls==deniedCalls+1,"failed Connect is consumed without a second approval request");
 int calls=gateCalls;permit=true;Check(Releases(c)&&gateCalls==calls+1,"normal GetSerialization without PLAP callback requires a fresh approval");
 calls=gateCalls;permit=false;Check(!Releases(c)&&gateCalls==calls+1,"next submission cannot reuse the preceding approval");
 permit=true;Check(SUCCEEDED(c->Connect(nullptr))&&Releases(c),"approved attempt releases credentials");
 permit=false;
 Check(!Releases(c),"approval cannot be reused");
 permit=true;c->Connect(nullptr);c->SetStringValue(0,L"changed");permit=false;Check(!Releases(c),"changing credentials invalidates approval");
 permit=true;c->Connect(nullptr);c->SetDeselected();permit=false;Check(!Releases(c),"deselection invalidates approval");
 permit=true;c->Connect(nullptr);c->Disconnect();permit=false;Check(!Releases(c),"disconnect invalidates approval");
 permit=true;c->Connect(nullptr);LPWSTR t=nullptr;CREDENTIAL_PROVIDER_STATUS_ICON i;c->ReportResult(STATUS_SUCCESS,0,&t,&i);permit=false;Check(!Releases(c),"success callback never grants approval");
 permit=true;
 interleaved=c;Check(FAILED(c->Connect(nullptr))&&!Releases(c),"credential change during wait invalidates approval");interleaved=nullptr;
 scope=pg::AccountPolicy::PasswordOnly;permit=false;int beforeBypass=gateCalls;
 Check(Releases(c)&&gateCalls==beforeBypass,"password-only account submits without an approval call");
 valid=false;Check(!Releases(c)&&gateCalls==beforeBypass,"password-only account still needs its normal password");
 valid=true;scope=pg::AccountPolicy::Invalid;Check(!Releases(c)&&gateCalls==beforeBypass,"missing account scope fails without an approval call");
 scope=pg::AccountPolicy::Approval;permit=false;Check(!Releases(c)&&gateCalls==beforeBypass+1,"Gated account account still needs approval after password-only account");
 c->Release();
 auto* filter=new PolicyFilter();GUID ids[]={CLSID_SystemLogon,CLSID_Unlock,CLSID_PgPassword,IID_IUnknown};BOOL allows[]={TRUE,TRUE,TRUE,TRUE};
 filter->Filter(CPUS_LOGON,0,ids,allows,4);Check(allows[0]&&!allows[1],"pilot keeps stock password and prevents remote-unlock bypass");
 enable=true;filter->Filter(CPUS_LOGON,0,ids,allows,4);Check(allows[0]&&!allows[1]&&allows[2]&&allows[3],"stock password stays available even if old enforcement flag is set");
 allows[0]=allows[1]=TRUE;filter->Filter(CPUS_CREDUI,0,ids,allows,4);Check(allows[0]&&allows[1],"ordinary credential prompts remain available");
 CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION in{},out{};in.clsidCredentialProvider=CLSID_SystemLogon;BYTE data[8]={1};in.rgbSerialization=data;in.cbSerialization=8;
 enable=false;Check(filter->UpdateRemoteCredential(&in,&out)==S_OK&&out.clsidCredentialProvider==CLSID_PgPassword&&out.rgbSerialization!=data,"RDP pilot maps to gate while stock remains available");pg::Clear(out);in.rgbSerialization=nullptr;Check(filter->UpdateRemoteCredential(&in,&out)==E_INVALIDARG,"empty remote serialization is rejected");filter->Release();
 Check(DllCanUnloadNow()==S_OK,"COM references released");std::printf("failures=%d\n",failures);return failures?1:0;
}
