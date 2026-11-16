#ifndef N976N_STARTUP_H
#define N976N_STARTUP_H
#include <windows.h>

enum N976N_STARTUP_STAGE {
    N976nUiReady = 1, N976nPeGuard, N976nVerifyFiles, N976nWpeInit,
    N976nTrustRoot, N976nTrustPublisher, N976nDriverLoad, N976nObserve
};
typedef struct {
    void *Context;
    DWORD (*Execute)(void *, unsigned);
    void (*Publish)(void *, unsigned, DWORD, const wchar_t *);
} N976N_STARTUP_OPS;
typedef struct {
    wchar_t Root[MAX_PATH], System[MAX_PATH];
    const N976N_STARTUP_OPS *Ui;
    void *Certificate;
    BOOL Guarded, Verified;
} N976N_NATIVE_STARTUP;
const wchar_t *N976nStartupName(unsigned Stage);
DWORD N976nStartupRun(const N976N_STARTUP_OPS *Ops, BOOL FirstPaintComplete);
DWORD N976nStartupExecute(void *Context, unsigned Stage);
void N976nStartupRelease(N976N_NATIVE_STARTUP *Context);
void N976nStartupLog(N976N_NATIVE_STARTUP *Context, unsigned Stage, DWORD Code);
int N976nStartupSelfTest(void);
DWORD N976nStartupVerifyOwnPackage(void);
#endif
