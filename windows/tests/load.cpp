#include <windows.h>
#include <credentialprovider.h>
#include <cstdio>
int wmain(int argc,wchar_t** argv){
 if(argc!=2)return 2;HRESULT init=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);if(FAILED(init))return 3;
 HMODULE module=LoadLibraryW(argv[1]);if(!module){std::printf("FAIL load error=%lu\n",GetLastError());return 1;}
 using Entry=HRESULT (STDAPICALLTYPE*)(REFCLSID,REFIID,void**);
 auto address=GetProcAddress(module,"DllGetClassObject");Entry get=nullptr;static_assert(sizeof(get)==sizeof(address));memcpy(&get,&address,sizeof(get));if(!get)return 1;
 CLSID id{};CLSIDFromString(L"{ABA410A1-5289-4DF6-A631-B53277425A01}",&id);
 IClassFactory* factory=nullptr;HRESULT h=get(id,IID_IClassFactory,(void**)&factory);if(FAILED(h))return 1;
 ICredentialProvider* p=nullptr;h=factory->CreateInstance(nullptr,IID_ICredentialProvider,(void**)&p);factory->Release();
 if(FAILED(h)){std::printf("FAIL factory hr=%08lx\n",h);return 1;}
 h=p->SetUsageScenario(CPUS_LOGON,0);if(FAILED(h)){std::printf("FAIL scenario hr=%08lx\n",h);return 1;}
 DWORD fields=0;h=p->GetFieldDescriptorCount(&fields);if(FAILED(h)||fields==0)return 1;
 for(DWORD n=0;n<fields;n++){CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* f=nullptr;if(FAILED(p->GetFieldDescriptorAt(n,&f)))return 1;CoTaskMemFree(f->pszLabel);CoTaskMemFree(f);}
 p->Release();FreeLibrary(module);CoUninitialize();std::printf("PASS actual DLL wraps system password provider; fields=%lu\n",fields);return 0;
}
