/* Actual ARM64 leaf paths, with inaccessible pages immediately outside ranges. */
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "../N976nUfsCore.c"
int main(void){
 size_t page=(size_t)sysconf(_SC_PAGESIZE),span=page*8;
 U8 *a=mmap(0,span+2*page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
 U8 *b=mmap(0,span+2*page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(a!=MAP_FAILED&&b!=MAP_FAILED);
 assert(!mprotect(a+page,span,PROT_READ|PROT_WRITE));assert(!mprotect(b+page,span,PROT_READ|PROT_WRITE));
 U8 *end=a+page+span,*cpu=b+page+span;unsigned count=0;
 for(unsigned n=0;n<=65536;n=n<128?n+1:n+4096){
  U8 *p=end-n,*w=cpu-n;NUF_REPORT r={0};NUF_ENGINE e={0};e.Dma=p;e.Report=&r;
  dmafill(p,0xCC,n);dmafill(w,0xA5,n);dmawrite(p,w,n);dmacopy(w,p,n);
  assert(bytecheck(&e,0,n,w,0)&&e.GuardCheckBytes==n);
  assert(bytecheck(&e,0,n,0,0xA5));
  if(n){p[n-1]^=0x81;assert(!bytecheck(&e,0,n,w,0)&&r.GuardOffset==n-1);}
  count++;
 }
 U64 capture[2]={11,22};
 assert(NufNcMatchWords(end,cpu,0,0,capture)==0&&capture[0]==11&&capture[1]==22);
 NufNcFillWords(end,0,0);NufNcCopyWords(end,cpu,0);
 /* Direct helpers at maximum length with protected exact ends and independent oracle. */
 U8 *p=end-65536,*w=cpu-65536;
 for(U32 i=0;i<65536;i++)w[i]=(U8)(i*37);
 NufNcCopyWords(p,w,8192);assert(!memcmp(p,w,65536));
 assert(NufNcMatchWords(p,w,0,8192,capture)==8192);
 for(U32 i=0;i<8192;i++){
  p[i*8]^=1;assert(NufNcMatchWords(p,w,0,8192,capture)==i);
  assert(capture[0]==wb64(p+i*8)&&capture[1]==wb64(w+i*8));p[i*8]^=1;
 }
 for(U32 words=1;words<=17;words++)for(U32 at=0;at<words;at++)for(U32 lane=0;lane<8;lane++)for(U32 expected=0;expected<2;expected++){
  U8 *d=end-words*8,*e=cpu-words*8;memset(d,0xA5,words*8);memset(e,0xA5,words*8);
  d[at*8+lane]^=0x81;NUF_REPORT r={0};NUF_ENGINE engine={0};engine.Dma=d;engine.Report=&r;
  assert(!bytecheck(&engine,0,words*8,expected?e:NULL,0xA5));
  U32 reads=at<(words&~3U)?(at/4+1)*4:at+1;
  assert(r.GuardOffset==at*8+lane&&engine.GuardReadOps==reads&&engine.GuardCheckBytes==reads*8);
 }
 assert(!munmap(a,span+2*page)&&!munmap(b,span+2*page));
 printf("protected_pages_%u_ranges_and_8192_first_mismatch_words\n",count);return 0;
}
