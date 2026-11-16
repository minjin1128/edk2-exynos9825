/* Run production private primitives against independent byte oracles.
 * ASan exact allocations make end overreads observable, including NC tails. */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "../N976nUfsCore.c"
static unsigned Cases;
static void check(U32 n,U32 align,U32 cpuAlign){
 U8 *allocation=malloc(n+align+1),*cpu=malloc(n+cpuAlign+1),*copy=malloc(n+cpuAlign+1);
 assert(allocation&&cpu&&copy);U8 *p=allocation+align,*w=cpu+cpuAlign,*out=copy+cpuAlign;
 memset(allocation,0x73,n+align+1);memset(cpu,0x91,n+cpuAlign+1);memset(copy,0x6B,n+cpuAlign+1);
 for(U32 i=0;i<n;i++)w[i]=(U8)(i*13+(i>>8));
 dmafill(p,0xA5,n);for(U32 i=0;i<n;i++)assert(p[i]==0xA5);
 dmawrite(p,w,n);assert(!memcmp(p,w,n));dmacopy(out,p,n);assert(!memcmp(out,w,n));
 for(U32 i=0;i<align;i++)assert(allocation[i]==0x73);assert(p[n]==0x73);
 for(U32 i=0;i<cpuAlign;i++)assert(copy[i]==0x6B);assert(out[n]==0x6B);
 NUF_REPORT r={0};NUF_ENGINE e={0};e.Dma=allocation;e.Report=&r;
 assert(bytecheck(&e,align,n,w,0)&&e.GuardCheckBytes==n);
 U64 loads=e.GuardReadOps;assert(!n||loads<=n);if(n>=4096)assert(loads<n/7+8);
 const U32 positions[]={0,1,7,8,15,16,23,24,31,32,63,64,n/2,n?n-1:0};
 for(U32 k=0;k<sizeof(positions)/sizeof(positions[0]);k++)if(positions[k]<n){
  U32 at=positions[k];p[at]^=0x81;if(at+3<n)p[at+3]^=0x44;
  memset(&r,0,sizeof(r));e.Quarantined=0;e.GuardCheckBytes=e.GuardReadOps=0;
  assert(!bytecheck(&e,align,n,w,0)&&r.GuardOffset==align+at&&r.GuardExpected==w[at]&&r.GuardActual==p[at]&&e.Quarantined);
  assert(e.GuardCheckBytes>at&&e.GuardCheckBytes<=n&&e.GuardReadOps);
  p[at]^=0x81;if(at+3<n)p[at+3]^=0x44;
 }
 dmafill(p,0xCC,n);memset(&r,0,sizeof(r));e.Quarantined=0;e.GuardCheckBytes=e.GuardReadOps=0;
 assert(bytecheck(&e,align,n,NULL,0xCC)&&e.GuardCheckBytes==n);
 for(U32 k=0;k<sizeof(positions)/sizeof(positions[0]);k++)if(positions[k]<n){
  U32 at=positions[k];p[at]^=0x81;
  memset(&r,0,sizeof(r));e.Quarantined=0;e.GuardCheckBytes=e.GuardReadOps=0;
  assert(!bytecheck(&e,align,n,NULL,0xCC)&&r.GuardOffset==align+at&&r.GuardExpected==0xCC&&r.GuardActual==p[at]&&e.Quarantined);
  assert(e.GuardCheckBytes>at&&e.GuardCheckBytes<=n&&e.GuardReadOps);
  p[at]^=0x81;
 }

 free(copy);free(cpu);free(allocation);Cases++;
}
int main(void){
 for(U32 a=0;a<8;a++)for(U32 b=0;b<8;b++)for(U32 n=0;n<=97;n++)check(n,a,b);
 const U32 sizes[]={4095,4096,4097,65503,65504,65505,65535,65536};
 for(U32 a=0;a<8;a++)for(U32 b=0;b<8;b++)for(U32 n=0;n<sizeof(sizes)/sizeof(sizes[0]);n++)check(sizes[n],a,b);
 /* Exact end allocation, no accessible trailing canary. All optimized paths
  * must use only requested bytes even when their address is not aligned. */
 for(U32 a=0;a<8;a++)for(U32 n=1;n<=65;n++){
  U8 *p=malloc(a+n),*w=malloc(n),*out=malloc(n);assert(p&&w&&out);
  memset(w,0xC3,n);dmafill(p+a,0xC3,n);dmawrite(p+a,w,n);dmacopy(out,p+a,n);assert(!memcmp(out,w,n));
  NUF_REPORT r={0};NUF_ENGINE e={0};e.Dma=p;e.Report=&r;assert(bytecheck(&e,a,n,w,0));
  free(out);free(w);free(p);Cases++;
 }
 printf("scalar64_alignment_tail_exact_bounds_and_first_mismatch_%u_cases\n",Cases);return 0;
}
