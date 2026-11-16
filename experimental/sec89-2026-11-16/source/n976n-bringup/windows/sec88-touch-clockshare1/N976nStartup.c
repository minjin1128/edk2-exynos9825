/* SEC76 EXP9 native PE bootstrap. No shell, PowerShell, retries or device IO.
 * The GUI must have completed its first paint before any worker operation.
 * Trust/driver changes are possible only inside the exact disposable PE path. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include "N976nStartup.h"

static const wchar_t *FileNames[6] = { L"N976nY771Touch.sys", L"N976nY771Touch.inf",
    L"n976ny771touch.cat", L"N976nTouchDemo.cer", L"N976nTouchDemo.pem", L"N976nTouchDemo.exe" };
static const char *AsciiNames[6] = { "N976nY771Touch.sys", "N976nY771Touch.inf",
    "n976ny771touch.cat", "N976nTouchDemo.cer", "N976nTouchDemo.pem", "N976nTouchDemo.exe" };
typedef struct { DWORD Bytes; BYTE Hash[32]; } INPUT_FILE;

const wchar_t *N976nStartupName(unsigned S)
{
    switch (S) {
    case N976nUiReady: return L"1 - native window painted";
    case N976nPeGuard: return L"2 - disposable ARM64 PE guard";
    case N976nVerifyFiles: return L"3 - package SHA256 and certificate";
    case N976nWpeInit: return L"4 - Windows PE initialization";
    case N976nTrustRoot: return L"5 - PE-only test root certificate";
    case N976nTrustPublisher: return L"6 - PE-only test publisher certificate";
    case N976nDriverLoad: return L"7 - drvload (PnP install request)";
    case N976nObserve: return L"8 - observing driver and Windows touch";
    default: return L"unknown startup stage";
    }
}

DWORD N976nStartupRun(const N976N_STARTUP_OPS *O, BOOL Painted)
{
    unsigned S; DWORD E;
    if (!O || !O->Execute || !O->Publish || !Painted) return ERROR_INVALID_STATE;
    for (S=N976nPeGuard; S<=N976nDriverLoad; ++S) {
        O->Publish(O->Context,S,0,L"Running; the window remains responsive.");
        E=O->Execute(O->Context,S);
        if (E) {
            O->Publish(O->Context,S,E,L"Stopped here. No automatic retry; diagnostics remain visible.");
            return E;
        }
    }
    O->Publish(O->Context,N976nObserve,0,
        L"drvload returned success. This does not prove device start or physical touch.");
    return 0;
}

static DWORD ReadSmall(const wchar_t *Path, BYTE *Buffer, DWORD Capacity, DWORD *Count)
{
    HANDLE H; LARGE_INTEGER Size; DWORD N=0, E=0, Attr=GetFileAttributesW(Path);
    if (Attr==INVALID_FILE_ATTRIBUTES) return GetLastError();
    if (Attr&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) return ERROR_INVALID_DATA;
    H=CreateFileW(Path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (H==INVALID_HANDLE_VALUE) return GetLastError();
    if (!GetFileSizeEx(H,&Size)) E=GetLastError();
    else if (Size.QuadPart<=0 || Size.QuadPart>=Capacity) E=ERROR_INVALID_DATA;
    else if (!ReadFile(H,Buffer,(DWORD)Size.QuadPart,&N,NULL)) E=GetLastError();
    else if (N!=(DWORD)Size.QuadPart) E=ERROR_READ_FAULT;
    else { Buffer[N]=0; *Count=N; }
    CloseHandle(H); return E;
}

static int Hex(char C)
{ return C>='0'&&C<='9'?C-'0':C>='a'&&C<='f'?C-'a'+10:-1; }

static DWORD ParseInputs(const char *B, DWORD N, INPUT_FILE Out[6])
{
    static const char Header[]="N976N-SEC76-EXP9-SHA256\n";
    const char *P=B, *End=B+N; unsigned I,J;
    if (N<sizeof(Header)-1 || memcmp(P,Header,sizeof(Header)-1)) return ERROR_INVALID_DATA;
    P+=sizeof(Header)-1;
    for (I=0; I<6; ++I) {
        size_t L=strlen(AsciiNames[I]); DWORD Size=0; unsigned Digits=0;
        if ((size_t)(End-P)<L+1 || memcmp(P,AsciiNames[I],L) || P[L]!=' ') return ERROR_INVALID_DATA;
        P+=L+1;
        while (P<End && *P>='0' && *P<='9') {
            if (++Digits>8 || Size>(64*1024*1024-(DWORD)(*P-'0'))/10) return ERROR_INVALID_DATA;
            Size=Size*10+(DWORD)(*P++-'0');
        }
        if (!Digits || !Size || P==End || *P++!=' ' || End-P<65) return ERROR_INVALID_DATA;
        Out[I].Bytes=Size;
        for (J=0;J<32;++J) {
            int A=Hex(P[2*J]), C=Hex(P[2*J+1]);
            if (A<0 || C<0) return ERROR_INVALID_DATA;
            Out[I].Hash[J]=(BYTE)((A<<4)|C);
        }
        P+=64;
        if (*P++!='\n') return ERROR_INVALID_DATA;
    }
    return P==End?0:ERROR_INVALID_DATA;
}

static DWORD HashMatches(const wchar_t *Path, const INPUT_FILE *Expected)
{
    BCRYPT_ALG_HANDLE Alg=NULL; BCRYPT_HASH_HANDLE Hash=NULL;
    BYTE Buffer[8192], Result[32]; HANDLE H=INVALID_HANDLE_VALUE;
    DWORD E=0,N,Attr=GetFileAttributesW(Path); LARGE_INTEGER Size;
    if (Attr==INVALID_FILE_ATTRIBUTES) return GetLastError();
    if (Attr&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) return ERROR_INVALID_DATA;
    H=CreateFileW(Path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);
    if (H==INVALID_HANDLE_VALUE) return GetLastError();
    if (!GetFileSizeEx(H,&Size)) { E=GetLastError(); goto Done; }
    if (Size.QuadPart!=Expected->Bytes) { E=ERROR_FILE_INVALID; goto Done; }
    if (BCryptOpenAlgorithmProvider(&Alg,BCRYPT_SHA256_ALGORITHM,NULL,0)<0 ||
        BCryptCreateHash(Alg,&Hash,NULL,0,NULL,0,0)<0) { E=ERROR_INVALID_FUNCTION; goto Done; }
    for (;;) {
        if (!ReadFile(H,Buffer,sizeof(Buffer),&N,NULL)) { E=GetLastError(); goto Done; }
        if (!N) break;
        if (BCryptHashData(Hash,Buffer,N,0)<0) { E=ERROR_INVALID_FUNCTION; goto Done; }
    }
    if (BCryptFinishHash(Hash,Result,sizeof(Result),0)<0) E=ERROR_INVALID_FUNCTION;
    else if (memcmp(Result,Expected->Hash,sizeof(Result))) E=ERROR_CRC;
Done:
    if (Hash) BCryptDestroyHash(Hash);
    if (Alg) BCryptCloseAlgorithmProvider(Alg,0);
    CloseHandle(H); return E;
}

static DWORD PeGuard(N976N_NATIVE_STARTUP *C)
{
    HKEY K; wchar_t Exe[MAX_PATH], Win[MAX_PATH]; SYSTEM_INFO S;
    GetNativeSystemInfo(&S);
    if (S.wProcessorArchitecture!=PROCESSOR_ARCHITECTURE_ARM64 ||
        !GetWindowsDirectoryW(Win,MAX_PATH) || _wcsicmp(Win,L"X:\\Windows") ||
        !GetModuleFileNameW(NULL,Exe,MAX_PATH) || _wcsicmp(Exe,L"X:\\N976nTouchDemo\\N976nTouchDemo.exe"))
        return ERROR_NOT_SUPPORTED;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\MiniNT",0,KEY_READ,&K)!=ERROR_SUCCESS)
        return ERROR_NOT_SUPPORTED;
    RegCloseKey(K);
    {
        DWORD Attr=GetFileAttributesW(L"X:\\N976nTouchDemo");
        if(Attr==INVALID_FILE_ATTRIBUTES || !(Attr&FILE_ATTRIBUTE_DIRECTORY) ||
           (Attr&FILE_ATTRIBUTE_REPARSE_POINT)) return ERROR_INVALID_DATA;
    }
    wcscpy_s(C->Root,MAX_PATH,L"X:\\N976nTouchDemo");
    wcscpy_s(C->System,MAX_PATH,L"X:\\Windows\\System32");
    C->Guarded=TRUE; return 0;
}

static DWORD VerifyInputs(N976N_NATIVE_STARTUP *C)
{
    BYTE B[4096], Der[8192]; DWORD E,N; unsigned I;
    INPUT_FILE Files[6]; wchar_t Path[MAX_PATH]; PCCERT_CONTEXT Cert;
    CERT_ENHKEY_USAGE *Usage=NULL; DWORD UsageBytes=0; BOOL CodeSigning=FALSE;
    swprintf_s(Path,MAX_PATH,L"%s\\startup-input.txt",C->Root);
    E=ReadSmall(Path,B,sizeof(B),&N); if (E) return E;
    E=ParseInputs((const char *)B,N,Files); if (E) return E;
    for (I=0;I<6;++I) {
        swprintf_s(Path,MAX_PATH,L"%s\\%s",C->Root,FileNames[I]);
        E=HashMatches(Path,&Files[I]); if (E) return E;
    }
    swprintf_s(Path,MAX_PATH,L"%s\\N976nTouchDemo.cer",C->Root);
    E=ReadSmall(Path,Der,sizeof(Der),&N); if (E) return E;
    Cert=CertCreateCertificateContext(X509_ASN_ENCODING,Der,N);
    if (!Cert) return GetLastError();
    C->Certificate=(void *)Cert;
    if (CertVerifyTimeValidity(NULL,Cert->pCertInfo)) return (DWORD)CERT_E_EXPIRED;
    if (!CertGetEnhancedKeyUsage(Cert,CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,NULL,&UsageBytes) ||
        UsageBytes>4096 || UsageBytes<sizeof(*Usage)) return ERROR_INVALID_DATA;
    Usage=(CERT_ENHKEY_USAGE *)HeapAlloc(GetProcessHeap(),0,UsageBytes);
    if (!Usage) return ERROR_NOT_ENOUGH_MEMORY;
    if (!CertGetEnhancedKeyUsage(Cert,CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,Usage,&UsageBytes)) E=GetLastError();
    else {
        for (I=0;I<Usage->cUsageIdentifier;++I)
            if (!strcmp(Usage->rgpszUsageIdentifier[I],szOID_PKIX_KP_CODE_SIGNING)) CodeSigning=TRUE;
        E=CodeSigning?0:ERROR_INVALID_DATA;
    }
    HeapFree(GetProcessHeap(),0,Usage);
    if (!E) C->Verified=TRUE;
    return E;
}

static DWORD Trust(N976N_NATIVE_STARTUP *C, const wchar_t *Name)
{
    HCERTSTORE Store; DWORD E=0;
    if (!C->Guarded || !C->Verified || !C->Certificate) return ERROR_INVALID_STATE;
    /* Bare PE may not yet have TrustedPublisher. Create only these standard
     * stores after the exact disposable-PE guard and sealed cert validation. */
    Store=CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_LOCAL_MACHINE,Name);
    if (!Store) return GetLastError();
    if (!CertAddCertificateContextToStore(Store,(PCCERT_CONTEXT)C->Certificate,CERT_STORE_ADD_REPLACE_EXISTING,NULL)) E=GetLastError();
    CertCloseStore(Store,0); return E;
}

static DWORD RunChild(N976N_NATIVE_STARTUP *C, BOOL Init)
{
    wchar_t Exe[MAX_PATH], Command[2*MAX_PATH], Log[MAX_PATH];
    SECURITY_ATTRIBUTES Sa={sizeof(Sa),NULL,TRUE}; STARTUPINFOW Si={0}; PROCESS_INFORMATION Pi={0};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION Limit={0}; HANDLE Job=NULL,Output=INVALID_HANDLE_VALUE,Input=INVALID_HANDLE_VALUE;
    DWORD E=0,Wait,Code=0; BOOL Started=FALSE;
    swprintf_s(Exe,MAX_PATH,L"%s\\%s",C->System,Init?L"wpeinit.exe":L"drvload.exe");
    if (Init) swprintf_s(Command,2*MAX_PATH,L"\"%s\"",Exe);
    else swprintf_s(Command,2*MAX_PATH,L"\"%s\" \"%s\\N976nY771Touch.inf\"",Exe,C->Root);
    swprintf_s(Log,MAX_PATH,L"%s\\%s.log",C->Root,Init?L"wpeinit":L"drvload");
    Output=CreateFileW(Log,GENERIC_WRITE,FILE_SHARE_READ,&Sa,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (Output==INVALID_HANDLE_VALUE) return GetLastError();
    Input=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&Sa,OPEN_EXISTING,0,NULL);
    if (Input==INVALID_HANDLE_VALUE) { E=GetLastError(); goto Done; }
    Job=CreateJobObjectW(NULL,NULL);
    Limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!Job || !SetInformationJobObject(Job,JobObjectExtendedLimitInformation,&Limit,sizeof(Limit))) { E=GetLastError(); goto Done; }
    Si.cb=sizeof(Si);Si.dwFlags=STARTF_USESTDHANDLES;Si.hStdInput=Input;Si.hStdOutput=Output;Si.hStdError=Output;
    if (!CreateProcessW(Exe,Command,NULL,NULL,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED,NULL,C->Root,&Si,&Pi)) { E=GetLastError(); goto Done; }
    Started=TRUE;
    if (!AssignProcessToJobObject(Job,Pi.hProcess)) { E=GetLastError(); goto Done; }
    if (ResumeThread(Pi.hThread)==(DWORD)-1) { E=GetLastError(); goto Done; }
    Wait=WaitForSingleObject(Pi.hProcess,Init?300000:120000);
    if (Wait==WAIT_TIMEOUT) E=ERROR_TIMEOUT;
    else if (Wait!=WAIT_OBJECT_0) E=GetLastError();
    else if (!GetExitCodeProcess(Pi.hProcess,&Code)) E=GetLastError();
    else E=Code;
Done:
    if (Started) {
        if (WaitForSingleObject(Pi.hProcess,0)!=WAIT_OBJECT_0) {
            // The exact newly created process only; no image-name/process-tree sweep.
            (void)TerminateProcess(Pi.hProcess,E?E:ERROR_CANCELLED);
            if (Job) (void)TerminateJobObject(Job,E?E:ERROR_CANCELLED);
            if (WaitForSingleObject(Pi.hProcess,10000)!=WAIT_OBJECT_0) E=ERROR_BUSY;
        }
        CloseHandle(Pi.hThread);CloseHandle(Pi.hProcess);
    }
    if (Job) CloseHandle(Job); // Retire any child descendants still in this owned job.
    if (Input!=INVALID_HANDLE_VALUE) CloseHandle(Input);
    CloseHandle(Output);return E;
}

DWORD N976nStartupExecute(void *Context, unsigned Stage)
{
    N976N_NATIVE_STARTUP *C=(N976N_NATIVE_STARTUP *)Context;
    if (Stage==N976nPeGuard) return PeGuard(C);
    if (!C->Guarded) return ERROR_NOT_SUPPORTED;
    if (Stage==N976nVerifyFiles) return VerifyInputs(C);
    if (!C->Verified) return ERROR_INVALID_STATE;
    if (Stage==N976nWpeInit) return RunChild(C,TRUE);
    if (Stage==N976nTrustRoot) return Trust(C,L"Root");
    if (Stage==N976nTrustPublisher) return Trust(C,L"TrustedPublisher");
    if (Stage==N976nDriverLoad) return RunChild(C,FALSE);
    return ERROR_INVALID_PARAMETER;
}

void N976nStartupLog(N976N_NATIVE_STARTUP *C,unsigned Stage,DWORD Code)
{
    char Line[128]; wchar_t Path[MAX_PATH]; HANDLE H; DWORD N;
    if (!C->Guarded) return;
    swprintf_s(Path,MAX_PATH,L"%s\\startup.log",C->Root);
    H=CreateFileW(Path,FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (H==INVALID_HANDLE_VALUE) return;
    sprintf_s(Line,sizeof(Line),"stage=%u code=0x%08lX uptime_ms=%llu\r\n",Stage,Code,GetTickCount64());
    (void)WriteFile(H,Line,(DWORD)strlen(Line),&N,NULL);CloseHandle(H);
}

void N976nStartupRelease(N976N_NATIVE_STARTUP *C)
{ if (C->Certificate) { CertFreeCertificateContext((PCCERT_CONTEXT)C->Certificate);C->Certificate=NULL; } }

/* Read-only build check of the ACTUAL generated package beside this EXE.
 * Does not set Guarded, enter N976nStartupRun, install certificates/drivers,
 * create child processes or write files. Uses the same parser/hash/certificate
 * verifier as PE stage3 and destroys its private verification context. */
DWORD N976nStartupVerifyOwnPackage(void)
{
    N976N_NATIVE_STARTUP C={0};wchar_t *Slash;DWORD E,N;
    N=GetModuleFileNameW(NULL,C.Root,MAX_PATH);
    if(!N||N>=MAX_PATH)return ERROR_INVALID_NAME;
    Slash=wcsrchr(C.Root,L'\\');if(!Slash)return ERROR_INVALID_NAME;*Slash=0;
    E=VerifyInputs(&C);N976nStartupRelease(&C);
    if(!E)printf("PASS actual generated manifest, all6 file hashes and certificate; read-only, no trust or driver changes\n");
    else printf("FAIL actual generated package verification 0x%08lX\n",E);
    return E;
}

typedef struct { unsigned Fail,Calls,Last,Published; DWORD Error; } TEST;
static DWORD TestExecute(void *Context,unsigned Stage)
{
    TEST *T=(TEST *)Context;
    if (Stage!=T->Last+1) return ERROR_INVALID_STATE;
    T->Last=Stage;++T->Calls;
    return Stage==T->Fail?T->Error:0;
}
static void TestPublish(void *Context,unsigned Stage,DWORD E,const wchar_t *Message)
{ TEST *T=(TEST *)Context;(void)E;(void)Message;T->Published=Stage; }

static int TestNativeHash(void)
{
    static const BYTE Abc[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,
        0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    wchar_t Temp[MAX_PATH],Path[MAX_PATH];INPUT_FILE Expected;BYTE B[8];
    HANDLE F;DWORD N=0;int Result=1;
    if(!GetTempPathW(MAX_PATH,Temp)||!GetTempFileNameW(Temp,L"n76",0,Path))return 1;
    F=CreateFileW(Path,GENERIC_WRITE,0,NULL,TRUNCATE_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(F==INVALID_HANDLE_VALUE){DeleteFileW(Path);return 1;}
    if(!WriteFile(F,"abc",3,&N,NULL)||N!=3){CloseHandle(F);DeleteFileW(Path);return 1;}
    CloseHandle(F);Expected.Bytes=3;memcpy(Expected.Hash,Abc,32);
    if(HashMatches(Path,&Expected))goto Done;
    Expected.Hash[0]^=1;if(HashMatches(Path,&Expected)!=ERROR_CRC)goto Done;
    Expected.Hash[0]^=1;Expected.Bytes=4;if(HashMatches(Path,&Expected)!=ERROR_FILE_INVALID)goto Done;
    if(ReadSmall(Path,B,sizeof(B),&N)||N!=3||memcmp(B,"abc",3))goto Done;
    if(ReadSmall(Path,B,3,&N)!=ERROR_INVALID_DATA)goto Done;
    Result=0;
Done:
    if(!DeleteFileW(Path))Result=1;
    return Result;
}

int N976nStartupSelfTest(void)
{
    unsigned I,J; N976N_STARTUP_OPS Ops; TEST T; INPUT_FILE Files[6];
    char Good[2048],Bad[2048]; size_t Used=0; int Count=0;
    N976N_NATIVE_STARTUP Native={0};
    ZeroMemory(&T,sizeof(T));T.Last=N976nUiReady;Ops.Context=&T;Ops.Execute=TestExecute;Ops.Publish=TestPublish;
    if (N976nStartupRun(&Ops,FALSE)!=ERROR_INVALID_STATE || T.Calls) return 1; ++Count;
    for (I=N976nPeGuard;I<=N976nDriverLoad;++I) {
        ZeroMemory(&T,sizeof(T));T.Last=N976nUiReady;T.Fail=I;T.Error=I==N976nWpeInit?ERROR_TIMEOUT:ERROR_FILE_NOT_FOUND;
        if (N976nStartupRun(&Ops,TRUE)!=T.Error || T.Calls!=I-1 || T.Published!=I || T.Last!=I) return 2; ++Count;
    }
    ZeroMemory(&T,sizeof(T));T.Last=N976nUiReady;
    if (N976nStartupRun(&Ops,TRUE) || T.Calls!=6 || T.Published!=N976nObserve) return 3; ++Count;
    // The real entry guard must refuse the build VM before any trust/driver work.
    if (N976nStartupExecute(&Native,N976nPeGuard)!=ERROR_NOT_SUPPORTED || Native.Guarded) return 4; ++Count;
    for(I=N976nVerifyFiles;I<=N976nDriverLoad;++I)
        if(N976nStartupExecute(&Native,I)!=ERROR_NOT_SUPPORTED) return 5;
    ++Count;
    Used+=(size_t)sprintf_s(Good+Used,sizeof(Good)-Used,"N976N-SEC76-EXP9-SHA256\n");
    for(I=0;I<6;++I) {
        Used+=(size_t)sprintf_s(Good+Used,sizeof(Good)-Used,"%s 123 ",AsciiNames[I]);
        for(J=0;J<64;++J) Good[Used++]='a';Good[Used++]='\n';Good[Used]=0;
    }
    if(ParseInputs(Good,(DWORD)Used,Files) || Files[5].Bytes!=123 || Files[5].Hash[31]!=0xaa) return 6; ++Count;
    if(!ParseInputs(Good,(DWORD)Used-1,Files)) return 7; ++Count;
    memcpy(Bad,Good,Used);Bad[Used]=0;Bad[0]='X';if(!ParseInputs(Bad,(DWORD)Used,Files)) return 8; ++Count;
    memcpy(Bad,Good,Used);Bad[Used]=0;Bad[Used-3]='g';if(!ParseInputs(Bad,(DWORD)Used,Files)) return 9; ++Count;
    memcpy(Bad,Good,Used);Bad[Used]='x';if(!ParseInputs(Bad,(DWORD)Used+1,Files)) return 10; ++Count;
    memcpy(Bad,Good,Used);Bad[Used]=0;Bad[29]='/';if(!ParseInputs(Bad,(DWORD)Used,Files)) return 11; ++Count;
    memcpy(Bad,Good,Used);Bad[Used]=0;
    {char *Old=strstr(Bad,"EXP9");if(!Old)return 13;Old[3]='8';}
    if(ParseInputs(Bad,(DWORD)Used,Files)!=ERROR_INVALID_DATA)return 14;++Count;
    if(TestNativeHash())return 12;Count+=5;
    printf("PASS %d startup groups; actual host guard refused; no certificate/driver installation\n",Count);
    return 0;
}
