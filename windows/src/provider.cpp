#include <initguid.h>
#include "gate.h"
#include <new>
#include <vector>
#include <mutex>
// Distinct identities keep original providers available through the pilot.
DEFINE_GUID(CLSID_PgPassword,0xaba410a1,0x5289,0x4df6,0xa6,0x31,0xb5,0x32,0x77,0x42,0x5a,0x01);
DEFINE_GUID(CLSID_PgUnlock,0xaba410a2,0x5289,0x4df6,0xa6,0x31,0xb5,0x32,0x77,0x42,0x5a,0x01);
DEFINE_GUID(CLSID_PgFilter,0xaba410a3,0x5289,0x4df6,0xa6,0x31,0xb5,0x32,0x77,0x42,0x5a,0x01);
DEFINE_GUID(CLSID_SystemLogon,0x60b78e88,0xead8,0x445c,0x9c,0xfd,0x0b,0x87,0xf7,0x4e,0xa6,0xcd);
DEFINE_GUID(CLSID_Unlock,0x379e7961,0x3c66,0x4636,0xb7,0xce,0xd8,0x00,0x65,0x34,0xf6,0xdd);
static LONG objects=0;
static HRESULT Copy(const wchar_t* s,LPWSTR* out){if(!out)return E_POINTER;size_t n=(wcslen(s)+1)*2;*out=(LPWSTR)CoTaskMemAlloc(n);if(!*out)return E_OUTOFMEMORY;memcpy(*out,s,n);return S_OK;}
#define REFCOUNT \
 ULONG STDMETHODCALLTYPE AddRef() override{return InterlockedIncrement(&refs);} \
 ULONG STDMETHODCALLTYPE Release() override{LONG n=InterlockedDecrement(&refs);if(!n)delete this;return n;}
class Events final:public ICredentialProviderCredentialEvents{
 LONG refs=1;ICredentialProviderCredentialEvents* target;ICredentialProviderCredential* outer;
public:
 Events(ICredentialProviderCredentialEvents* t,ICredentialProviderCredential* o):target(t),outer(o){target->AddRef();InterlockedIncrement(&objects);}
 ~Events(){target->Release();InterlockedDecrement(&objects);}
 REFCOUNT
 HRESULT STDMETHODCALLTYPE QueryInterface(REFIID r,void** p) override{if(!p)return E_POINTER;*p=nullptr;if(r==IID_IUnknown||r==IID_ICredentialProviderCredentialEvents){*p=this;AddRef();return S_OK;}return E_NOINTERFACE;}
 HRESULT STDMETHODCALLTYPE SetFieldState(ICredentialProviderCredential*,DWORD f,CREDENTIAL_PROVIDER_FIELD_STATE s) override{return target->SetFieldState(outer,f,s);}
 HRESULT STDMETHODCALLTYPE SetFieldInteractiveState(ICredentialProviderCredential*,DWORD f,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE s) override{return target->SetFieldInteractiveState(outer,f,s);}
 HRESULT STDMETHODCALLTYPE SetFieldString(ICredentialProviderCredential*,DWORD f,LPCWSTR s) override{return target->SetFieldString(outer,f,s);}
 HRESULT STDMETHODCALLTYPE SetFieldCheckbox(ICredentialProviderCredential*,DWORD f,BOOL b,LPCWSTR s) override{return target->SetFieldCheckbox(outer,f,b,s);}
 HRESULT STDMETHODCALLTYPE SetFieldBitmap(ICredentialProviderCredential*,DWORD f,HBITMAP b) override{return target->SetFieldBitmap(outer,f,b);}
 HRESULT STDMETHODCALLTYPE SetFieldComboBoxSelectedItem(ICredentialProviderCredential*,DWORD f,DWORD i) override{return target->SetFieldComboBoxSelectedItem(outer,f,i);}
 HRESULT STDMETHODCALLTYPE DeleteFieldComboBoxItem(ICredentialProviderCredential*,DWORD f,DWORD i) override{return target->DeleteFieldComboBoxItem(outer,f,i);}
 HRESULT STDMETHODCALLTYPE AppendFieldComboBoxItem(ICredentialProviderCredential*,DWORD f,LPCWSTR s) override{return target->AppendFieldComboBoxItem(outer,f,s);}
 HRESULT STDMETHODCALLTYPE SetFieldSubmitButton(ICredentialProviderCredential*,DWORD f,DWORD a) override{return target->SetFieldSubmitButton(outer,f,a);}
 HRESULT STDMETHODCALLTYPE OnCreatingWindow(HWND* w) override{return target->OnCreatingWindow(w);}
};
class Credential final:public IConnectableCredentialProviderCredential,public ICredentialProviderCredential2{
 LONG refs=1;ICredentialProviderCredential* inner;DWORD recoveryField;GUID identity;
 Events* events=nullptr;std::wstring code;CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION pending{};bool approved=false,attempted=false,running=false;volatile LONG cancelled=0;std::mutex state;LONG revision=0;ULONGLONG approvedUntil=0;
 void Reset(){std::lock_guard<std::mutex> lock(state);++revision;approved=false;attempted=false;pg::Clear(pending);}
 void Failed(LONG attempt){std::lock_guard<std::mutex> lock(state);running=false;attempted=(attempt==revision);}
 ICredentialProviderCredential* Self(){return static_cast<IConnectableCredentialProviderCredential*>(this);}
public:
 Credential(ICredentialProviderCredential* c,DWORD field,REFGUID id):inner(c),recoveryField(field),identity(id){inner->AddRef();InterlockedIncrement(&objects);}
 ~Credential(){UnAdvise();Reset();SecureZeroMemory(code.data(),code.size()*2);inner->Release();InterlockedDecrement(&objects);}
 REFCOUNT
 HRESULT STDMETHODCALLTYPE QueryInterface(REFIID r,void** p) override{
  if(!p)return E_POINTER;*p=nullptr;
  if(r==IID_IUnknown||r==IID_ICredentialProviderCredential||r==IID_IConnectableCredentialProviderCredential)*p=static_cast<IConnectableCredentialProviderCredential*>(this);
  else if(r==IID_ICredentialProviderCredential2){ICredentialProviderCredential2* c=nullptr;if(FAILED(inner->QueryInterface(IID_PPV_ARGS(&c))))return E_NOINTERFACE;c->Release();*p=static_cast<ICredentialProviderCredential2*>(this);}else return E_NOINTERFACE;AddRef();return S_OK;
 }
 HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderCredentialEvents* e) override{UnAdvise();events=new(std::nothrow) Events(e,Self());return events?inner->Advise(events):E_OUTOFMEMORY;}
 HRESULT STDMETHODCALLTYPE UnAdvise() override{HRESULT h=inner->UnAdvise();if(events){events->Release();events=nullptr;}return h;}
 HRESULT STDMETHODCALLTYPE SetSelected(BOOL* a) override{return inner->SetSelected(a);}
 HRESULT STDMETHODCALLTYPE SetDeselected() override{InterlockedExchange(&cancelled,1);Reset();{std::lock_guard<std::mutex> lock(state);SecureZeroMemory(code.data(),code.size()*2);code.clear();}return inner->SetDeselected();}
 HRESULT STDMETHODCALLTYPE GetFieldState(DWORD f,CREDENTIAL_PROVIDER_FIELD_STATE* s,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* i) override{if(f!=recoveryField)return inner->GetFieldState(f,s,i);if(!s||!i)return E_POINTER;LPWSTR sid=nullptr;bool passwordOnly=SUCCEEDED(GetUserSid(&sid)) && sid && pg::ScopeForSid(sid)==pg::AccountPolicy::PasswordOnly;CoTaskMemFree(sid);*s=passwordOnly?CPFS_HIDDEN:CPFS_DISPLAY_IN_SELECTED_TILE;*i=CPFIS_NONE;return S_OK;}
 HRESULT STDMETHODCALLTYPE GetStringValue(DWORD f,LPWSTR* v) override{if(f!=recoveryField)return inner->GetStringValue(f,v);std::lock_guard<std::mutex> lock(state);return Copy(code.c_str(),v);}
 HRESULT STDMETHODCALLTYPE GetBitmapValue(DWORD f,HBITMAP* b) override{return inner->GetBitmapValue(f,b);}
 HRESULT STDMETHODCALLTYPE GetCheckboxValue(DWORD f,BOOL* b,LPWSTR* v) override{return inner->GetCheckboxValue(f,b,v);}
 HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(DWORD f,DWORD* a) override{return inner->GetSubmitButtonValue(f,a);}
 HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(DWORD f,DWORD* n,DWORD* s) override{return inner->GetComboBoxValueCount(f,n,s);}
 HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(DWORD f,DWORD i,LPWSTR* v) override{return inner->GetComboBoxValueAt(f,i,v);}
 HRESULT STDMETHODCALLTYPE SetStringValue(DWORD f,LPCWSTR v) override{Reset();if(f!=recoveryField)return inner->SetStringValue(f,v);if(!v||wcslen(v)>32)return E_INVALIDARG;std::lock_guard<std::mutex> lock(state);SecureZeroMemory(code.data(),code.size()*2);code=v;return S_OK;}
 HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD f,BOOL b) override{Reset();return inner->SetCheckboxValue(f,b);}
 HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD f,DWORD i) override{Reset();return inner->SetComboBoxSelectedValue(f,i);}
 HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD f) override{Reset();return inner->CommandLinkClicked(f);}
 HRESULT STDMETHODCALLTYPE GetUserSid(LPWSTR* s) override{ICredentialProviderCredential2* c=nullptr;HRESULT h=inner->QueryInterface(IID_PPV_ARGS(&c));if(FAILED(h))return h;h=c->GetUserSid(s);c->Release();return h;}
 HRESULT STDMETHODCALLTYPE Connect(IQueryContinueWithStatus* q) override{
  LONG attempt;std::wstring recovery;
  {std::lock_guard<std::mutex> lock(state);if(running)return E_PENDING;++revision;approved=false;pg::Clear(pending);InterlockedExchange(&cancelled,0);attempt=revision;recovery=code;attempted=true;running=true;}
  CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION candidate{};
  CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response=CPGSR_NO_CREDENTIAL_NOT_FINISHED;LPWSTR status=nullptr;CREDENTIAL_PROVIDER_STATUS_ICON icon=CPSI_NONE;
  HRESULT h=inner->GetSerialization(&response,&candidate,&status,&icon);CoTaskMemFree(status);
  if(FAILED(h)||response!=CPGSR_RETURN_CREDENTIAL_FINISHED){pg::Clear(candidate);SecureZeroMemory(recovery.data(),recovery.size()*2);Failed(attempt);return FAILED(h)?h:E_ACCESSDENIED;}
  std::wstring user,sid;
  if(!pg::ValidatePassword(candidate,user,sid)){pg::Clear(candidate);SecureZeroMemory(recovery.data(),recovery.size()*2);Failed(attempt);if(q)q->SetStatusMessage(L"Password was not accepted.");return E_ACCESSDENIED;}
  const auto policy=pg::ScopeForSid(sid);
  bool granted=policy==pg::AccountPolicy::PasswordOnly || (policy==pg::AccountPolicy::Approval && pg::Approve(user,sid,recovery,q,&cancelled));
  SecureZeroMemory(recovery.data(),recovery.size()*2);
  {std::lock_guard<std::mutex> lock(state);
   running=false;attempted=(attempt==revision);
   if(attempt!=revision||InterlockedCompareExchange(&cancelled,0,0))granted=false;
   if(granted){pending=candidate;ZeroMemory(&candidate,sizeof(candidate));pending.clsidCredentialProvider=identity;approved=true;approvedUntil=GetTickCount64()+5000;}
   if(attempt==revision){SecureZeroMemory(code.data(),code.size()*2);code.clear();}
  }
  pg::Clear(candidate);
  if(!granted){if(q)q->SetStatusMessage(L"Sign-in was not approved. Try again or use your recovery code if offline.");return E_ACCESSDENIED;}
  return S_OK;
 }
 HRESULT STDMETHODCALLTYPE Disconnect() override{InterlockedExchange(&cancelled,1);Reset();return S_OK;}
 HRESULT STDMETHODCALLTYPE GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* r,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* s,LPWSTR* t,CREDENTIAL_PROVIDER_STATUS_ICON* i) override{
  if(!r||!s||!t||!i)return E_POINTER;*r=CPGSR_NO_CREDENTIAL_NOT_FINISHED;ZeroMemory(s,sizeof(*s));*t=nullptr;*i=CPSI_ERROR;
  // Connect is documented for PLAP. Normal password and RDP submissions call
  // GetSerialization directly, so they must enter the same gate here too.
  bool needGate=false;{std::lock_guard<std::mutex> lock(state);if(running){Copy(L"Waiting for approval.",t);*i=CPSI_NONE;return S_OK;}needGate=!approved&&!attempted;}
  if(needGate)Connect(nullptr);
  std::lock_guard<std::mutex> lock(state);
  if(!approved||!pending.rgbSerialization||GetTickCount64()>approvedUntil){attempted=false;approved=false;pg::Clear(pending);Copy(L"Sign-in was not approved.",t);return S_OK;}
  *s=pending;ZeroMemory(&pending,sizeof(pending));approved=false;attempted=false;*r=CPGSR_RETURN_CREDENTIAL_FINISHED;*i=CPSI_SUCCESS;return S_OK;
 }
 HRESULT STDMETHODCALLTYPE ReportResult(NTSTATUS s,NTSTATUS sub,LPWSTR* t,CREDENTIAL_PROVIDER_STATUS_ICON* i) override{Reset();return inner->ReportResult(s,sub,t,i);}
};
class Provider final:public ICredentialProvider,public ICredentialProviderSetUserArray{
 LONG refs=1;GUID identity;ICredentialProvider* inner=nullptr;DWORD fields=0;std::vector<Credential*> credentials;
 void Clear(){for(auto* c:credentials)c->Release();credentials.clear();}
public:
 Provider(REFGUID id):identity(id){InterlockedIncrement(&objects);}
 ~Provider(){Clear();if(inner)inner->Release();InterlockedDecrement(&objects);}
 REFCOUNT
 HRESULT STDMETHODCALLTYPE QueryInterface(REFIID r,void** p) override{if(!p)return E_POINTER;*p=nullptr;if(r==IID_IUnknown||r==IID_ICredentialProvider)*p=static_cast<ICredentialProvider*>(this);else if(r==IID_ICredentialProviderSetUserArray)*p=static_cast<ICredentialProviderSetUserArray*>(this);else return E_NOINTERFACE;AddRef();return S_OK;}
 HRESULT Initialize(){return CoCreateInstance(identity==CLSID_PgPassword?CLSID_SystemLogon:CLSID_Unlock,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&inner));}
 HRESULT STDMETHODCALLTYPE SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO s,DWORD f) override{if(s!=CPUS_LOGON&&s!=CPUS_UNLOCK_WORKSTATION)return E_NOTIMPL;Clear();HRESULT h=inner->SetUsageScenario(s,f);if(SUCCEEDED(h))h=inner->GetFieldDescriptorCount(&fields);return h;}
 HRESULT STDMETHODCALLTYPE SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* s) override{if(!s)return E_POINTER;auto copy=*s;copy.clsidCredentialProvider=identity==CLSID_PgPassword?CLSID_SystemLogon:CLSID_Unlock;Clear();return inner->SetSerialization(&copy);}
 HRESULT STDMETHODCALLTYPE SetUserArray(ICredentialProviderUserArray* users) override{Clear();ICredentialProviderSetUserArray* p=nullptr;HRESULT h=inner->QueryInterface(IID_PPV_ARGS(&p));if(FAILED(h))return identity==CLSID_PgUnlock?S_OK:h;h=p->SetUserArray(users);p->Release();return h;}
 HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderEvents* e,UINT_PTR c) override{return inner->Advise(e,c);}
 HRESULT STDMETHODCALLTYPE UnAdvise() override{Clear();return inner->UnAdvise();}
 HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* n) override{if(!n)return E_POINTER;*n=fields+1;return S_OK;}
 HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(DWORD f,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** d) override{if(f!=fields)return inner->GetFieldDescriptorAt(f,d);if(!d)return E_POINTER;*d=(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(**d));if(!*d)return E_OUTOFMEMORY;ZeroMemory(*d,sizeof(**d));(*d)->dwFieldID=f;(*d)->cpft=CPFT_PASSWORD_TEXT;HRESULT h=Copy(L"One-time recovery code (only if offline)",&(*d)->pszLabel);if(FAILED(h)){CoTaskMemFree(*d);*d=nullptr;}return h;}
 HRESULT STDMETHODCALLTYPE GetCredentialCount(DWORD* n,DWORD* d,BOOL* a) override{return inner->GetCredentialCount(n,d,a);}
 HRESULT STDMETHODCALLTYPE GetCredentialAt(DWORD index,ICredentialProviderCredential** out) override{if(!out)return E_POINTER;*out=nullptr;DWORD count=0,def=0;BOOL automatic=FALSE;HRESULT result=inner->GetCredentialCount(&count,&def,&automatic);if(FAILED(result))return result;if(index>=count||count>256)return E_INVALIDARG;try{while(credentials.size()<=index)credentials.push_back(nullptr);}catch(const std::bad_alloc&){return E_OUTOFMEMORY;}if(!credentials[index]){ICredentialProviderCredential* c=nullptr;HRESULT h=inner->GetCredentialAt(index,&c);if(FAILED(h))return h;credentials[index]=new(std::nothrow) Credential(c,fields,identity);c->Release();if(!credentials[index])return E_OUTOFMEMORY;}return credentials[index]->QueryInterface(IID_PPV_ARGS(out));}
};
class PolicyFilter final:public ICredentialProviderFilter{
 LONG refs=1;
public:
 PolicyFilter(){InterlockedIncrement(&objects);}~PolicyFilter(){InterlockedDecrement(&objects);}REFCOUNT
 HRESULT STDMETHODCALLTYPE QueryInterface(REFIID r,void** p) override{if(!p)return E_POINTER;*p=nullptr;if(r!=IID_IUnknown&&r!=IID_ICredentialProviderFilter)return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
 HRESULT STDMETHODCALLTYPE Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO s,DWORD,GUID* ids,BOOL* allow,DWORD n) override{if(s!=CPUS_LOGON&&s!=CPUS_UNLOCK_WORKSTATION)return S_OK;for(DWORD j=0;j<n;j++)if(ids[j]==CLSID_Unlock)allow[j]=FALSE;return S_OK;}
 HRESULT STDMETHODCALLTYPE UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* in,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* out) override{if(!in||!out)return E_POINTER;if(in->clsidCredentialProvider!=CLSID_SystemLogon)return E_NOTIMPL;if(!in->rgbSerialization||in->cbSerialization==0||in->cbSerialization>65536)return E_INVALIDARG;*out=*in;out->rgbSerialization=(BYTE*)CoTaskMemAlloc(in->cbSerialization);if(!out->rgbSerialization)return E_OUTOFMEMORY;memcpy(out->rgbSerialization,in->rgbSerialization,in->cbSerialization);out->clsidCredentialProvider=CLSID_PgPassword;return S_OK;}
};
class Factory final:public IClassFactory{
 LONG refs=1;GUID id;
public:
 Factory(REFGUID i):id(i){InterlockedIncrement(&objects);}~Factory(){InterlockedDecrement(&objects);}REFCOUNT
 HRESULT STDMETHODCALLTYPE QueryInterface(REFIID r,void** p) override{if(!p)return E_POINTER;*p=nullptr;if(r!=IID_IUnknown&&r!=IID_IClassFactory)return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
 HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer,REFIID r,void** out) override{if(!out)return E_POINTER;*out=nullptr;if(outer)return CLASS_E_NOAGGREGATION;IUnknown* obj=nullptr;HRESULT h=S_OK;if(id==CLSID_PgFilter)obj=new(std::nothrow) PolicyFilter();else{auto* p=new(std::nothrow) Provider(id);if(!p)return E_OUTOFMEMORY;h=p->Initialize();obj=static_cast<ICredentialProvider*>(p);}if(!obj)return E_OUTOFMEMORY;if(SUCCEEDED(h))h=obj->QueryInterface(r,out);obj->Release();return h;}
 HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override{if(lock)InterlockedIncrement(&objects);else InterlockedDecrement(&objects);return S_OK;}
};
extern "C" HRESULT __declspec(dllexport) DllGetClassObject(REFCLSID id,REFIID r,void** out){if(id!=CLSID_PgPassword&&id!=CLSID_PgUnlock&&id!=CLSID_PgFilter)return CLASS_E_CLASSNOTAVAILABLE;auto* f=new(std::nothrow) Factory(id);if(!f)return E_OUTOFMEMORY;HRESULT h=f->QueryInterface(r,out);f->Release();return h;}
extern "C" HRESULT __declspec(dllexport) DllCanUnloadNow(){return objects?S_FALSE:S_OK;}
BOOL WINAPI DllMain(HINSTANCE,DWORD,void*){return TRUE;}
