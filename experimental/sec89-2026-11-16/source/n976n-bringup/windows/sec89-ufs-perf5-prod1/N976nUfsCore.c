/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * N976N guarded Windows probe. Packet layout follows EDK2 UfsHci.h;
 * Samsung byte units, full guarded PRD page and response capacity follow
 * physically observed SEC77 UfsProbe.c. NTDEV/9820 Storport provides the
 * adapter lifecycle; no reset, PHY, power or generic pass-through.
 * SEC87 permits bounded 1..16-block WRITE10 only inside either exact admitted SYSTEM
 * FAT prefix or USERDATA NTFS extent, retaining real no-data SYNCHRONIZE CACHE10 and exact retirement.
 */
#include "N976nUfsCore.h"
#include <string.h>
#if defined(_MSC_VER) && defined(_M_ARM64)
#include <intrin.h>
#define NUF_NC_SINGLE __declspec(noinline)
#else
#define NUF_NC_SINGLE
#endif
/* Range helpers have the same scalar-access contract as the fallback below.
 * Native ARM64 build must link the audited leaf assembly, never libc/SIMD.
 * WB pointers not aligned to eight bytes use the original bounded byte path. */
#if defined(NUF_NC_RANGES)
extern void NufNcFillWords(volatile U8 *,U64,U32);
extern void NufNcCopyWords(volatile U8 *,const volatile U8 *,U32);
extern U32 NufNcMatchWords(const volatile U8 *,const U8 *,U64,U32,U64 *);
#endif
static U32 be32(const volatile U8 *p){return ((U32)p[0]<<24)|((U32)p[1]<<16)|((U32)p[2]<<8)|p[3];}
static void put32(volatile U8 *p,U32 v){p[0]=(U8)v;p[1]=(U8)(v>>8);p[2]=(U8)(v>>16);p[3]=(U8)(v>>24);}
/* NC accesses are scalar volatile words only after checking virtual alignment;
 * byte prologues/tails cover every byte. No libc access ever targets NC memory.
 * WB source/destination bytes need not be aligned. ARM64 assembly is checked by
 * the component test, including the isolated word load/store helpers. */
static U32 ncword(const volatile U8 *p){return *(const volatile U32 *)(const volatile void *)p;}
/* Only for 8-byte-aligned owned DMA RAM, never registers or UPIU fields.
 * MSVC combines adjacent volatile words into pairs even with iso intrinsics.
 * A non-inlined single-access helper preserves the scalar-only contract. The
 * final SYS must contain one LDR/STR X in each helper and retain caller BLs.
 * This is not a memory barrier; existing ownership fences remain responsible. */
static NUF_NC_SINGLE U64 ncguard64(const volatile U8 *p){
#if defined(_MSC_VER) && defined(_M_ARM64)
 return (U64)__iso_volatile_load64((const volatile __int64 *)(const volatile void *)p);
#else
 return *(const volatile U64 *)(const volatile void *)p;
#endif
}
static void ncput(volatile U8 *p,U32 v){*(volatile U32 *)(volatile void *)p=v;}
static NUF_NC_SINGLE void ncput64(volatile U8 *p,U64 v){
#if defined(_MSC_VER) && defined(_M_ARM64)
 __iso_volatile_store64((volatile __int64 *)(volatile void *)p,(__int64)v);
#else
 *(volatile U64 *)(volatile void *)p=v;
#endif
}
static U32 wbword(const U8 *p){return (U32)p[0]|((U32)p[1]<<8)|((U32)p[2]<<16)|((U32)p[3]<<24);}
static U64 wb64(const U8 *p){return (U64)wbword(p)|((U64)wbword(p+4)<<32);}
static void wbput64(U8 *p,U64 v){for(U32 n=0;n<8;n++)p[n]=(U8)(v>>(8*n));}
static void dmafill(volatile U8 *p,U8 v,U32 n){
 while(n&&((size_t)p&7U)){*p++=v;n--;}
 U64 word=(U64)v*0x0101010101010101ULL;
#if defined(NUF_NC_RANGES)
 U32 words=n/8;if(words){NufNcFillWords(p,word,words);p+=words*8;n-=words*8;}
#endif
 while(n>=32){ncput64(p,word);ncput64(p+8,word);ncput64(p+16,word);ncput64(p+24,word);p+=32;n-=32;}
 while(n>=8){ncput64(p,word);p+=8;n-=8;}
 if(n>=4){ncput(p,(U32)word);p+=4;n-=4;}
 while(n--)*p++=v;
}
static void dmacopy(U8 *out,const volatile U8 *in,U32 n){
 while(n&&((size_t)in&7U)){*out++=*in++;n--;}
#if defined(NUF_NC_RANGES)
 if(!((size_t)out&7U)){U32 words=n/8;if(words){NufNcCopyWords(out,in,words);out+=words*8;in+=words*8;n-=words*8;}}
#endif
 while(n>=32){
  U64 a=ncguard64(in),b=ncguard64(in+8),c=ncguard64(in+16),d=ncguard64(in+24);
  wbput64(out,a);wbput64(out+8,b);wbput64(out+16,c);wbput64(out+24,d);in+=32;out+=32;n-=32;
 }
 while(n>=8){wbput64(out,ncguard64(in));in+=8;out+=8;n-=8;}
 while(n--)*out++=*in++;
}
static void dmawrite(volatile U8 *out,const U8 *in,U32 n){
 while(n&&((size_t)out&7U)){*out++=*in++;n--;}
#if defined(NUF_NC_RANGES)
 if(!((size_t)in&7U)){U32 words=n/8;if(words){NufNcCopyWords(out,in,words);out+=words*8;in+=words*8;n-=words*8;}}
#endif
 while(n>=32){ncput64(out,wb64(in));ncput64(out+8,wb64(in+8));ncput64(out+16,wb64(in+16));ncput64(out+24,wb64(in+24));out+=32;in+=32;n-=32;}
 while(n>=8){ncput64(out,wb64(in));out+=8;in+=8;n-=8;}
 while(n--)*out++=*in++;
}
static U32 dmacrc(const volatile U8 *p,U32 n){U32 c=~0U;for(U32 i=0;i<n;i++){
 c^=p[i];for(U32 b=0;b<8;b++)c=(c>>1)^(0xEDB88320U&(0U-(c&1U)));}return ~c;}
U32 NufCrc32(const void *data,U32 bytes){const U8 *p=(const U8*)data;U32 c=~0U;
 for(U32 i=0;i<bytes;i++){c^=p[i];for(U32 b=0;b<8;b++)c=(c>>1)^(0xEDB88320U&(0U-(c&1U)));}return ~c;}
int NufReadCommandAllowed(U32 op,U32 lun,U32 bytes,U64 lba,U32 tag){
 return lun==0 && tag>=1 && tag<=255 &&
  ((op==0x25&&bytes==8&&tag==1&&lba==0)||(op==0x28&&bytes&&bytes<=NUF_MAX_TRANSFER&&!(bytes%4096)&&
    lba<=0xFFFFFFFFULL&&bytes/4096-1<=0xFFFFFFFFULL-lba));}
int NufWriteRangeAllowed(const NUF_CONFIG *c,U64 lba,U32 bytes){
 return c&&c->WriteEnabled==1&&c->Lun==0&&c->BlockBytes==4096&&bytes&&bytes<=NUF_MAX_TRANSFER&&!(bytes%4096)&&
  lba<=0xFFFFFFFFULL&&bytes/4096-1<=0xFFFFFFFFULL-lba&&
  c->WriteFirst==NUF_WRITE_REGION_FIRST&&c->WriteBlocks==NUF_WRITE_REGION_BLOCKS&&
  c->WriteFirst<=c->LastLba&&c->WriteBlocks-1<=c->LastLba-c->WriteFirst&&
  c->SystemWriteFirst==NUF_SYSTEM_PARTITION_START&&c->SystemWriteBlocks==NUF_SYSTEM_VOLUME_BLOCKS&&
  c->SystemWriteFirst<=c->LastLba&&c->SystemWriteBlocks-1<=c->LastLba-c->SystemWriteFirst&&
  c->SystemWriteFirst+c->SystemWriteBlocks<=c->WriteFirst&&
  ((lba>=c->WriteFirst&&lba-c->WriteFirst<c->WriteBlocks&&bytes/4096<=c->WriteBlocks-(lba-c->WriteFirst))||
   (lba>=c->SystemWriteFirst&&lba-c->SystemWriteFirst<c->SystemWriteBlocks&&bytes/4096<=c->SystemWriteBlocks-(lba-c->SystemWriteFirst)));
}
static U32 rd(NUF_ENGINE *e,U32 o){return e->Ops.Read(e->Ops.Context,o);}
static void wr(NUF_ENGINE *e,U32 o,U32 v){e->Ops.Write(e->Ops.Context,o,v);e->Ops.Fence(e->Ops.Context);}
static int fail(NUF_ENGINE *e,U32 why){NUF_REPORT *r=e->Report;r->Reason=why;
 if(why==NufGuard||why==NufOwnership)r->Quarantined=1;
 if(r->Quarantined)e->Quarantined=1;
 if(!r->FirstReason){r->FirstReason=why;r->FirstStage=r->Stage;}return 0;}
static int owned(NUF_ENGINE *e){return e->Ops.Owned(e->Ops.Context);}
static void snapshot(NUF_ENGINE *e){NUF_REPORT *r=e->Report;r->Is=rd(e,0x20);r->Dbr=rd(e,0x58);
 r->Hcs=rd(e,0x30);r->TrlRun=rd(e,0x60);r->TrlBase=rd(e,0x50);r->TrlBaseHi=rd(e,0x54);r->Coherency=rd(e,NUF_COH);}
static int format(NUF_ENGINE *e){NUF_CONFIG *c=&e->Config;return
 rd(e,0)==c->Cap&&rd(e,8)==c->Version&&rd(e,0x34)==1&&rd(e,0x24)==0&&rd(e,0x18)==0&&
 rd(e,0x1100)==c->Tx&&rd(e,0x1104)==c->Rx&&rd(e,0x1160)==c->Reorder&&
 rd(e,0x116c)==c->Axi&&rd(e,0x4c)==c->Iacr&&rd(e,NUF_COH)==c->Coherency&&
 rd(e,0x70)==c->TmBase&&rd(e,0x74)==c->TmBaseHi&&rd(e,0x80)==0&&rd(e,0x78)==0;}
static int idle(NUF_ENGINE *e,U32 running,U64 base){return owned(e)&&format(e)&&
 rd(e,0x60)==running&&rd(e,0x58)==0&&rd(e,0x50)==(U32)base&&rd(e,0x54)==(U32)(base>>32)&&
 (rd(e,0x30)&0xBU)==0xBU;}
static U32 waitbucket(U64 us){
 const U32 upper[NUF_WAIT_BUCKETS-1]={100,250,500,1000,2000,4000,8000};
 U32 i=0;while(i<NUF_WAIT_BUCKETS-1&&us>=upper[i])i++;return i;
}
static int waitreg(NUF_ENGINE *e,U32 off,U32 mask,U32 want){NUF_REPORT *r=e->Report;
 U32 kind=off!=0x58?0:r->Opcode==0x2A?2:r->Opcode==0x35?3:1;
 const U64 budgets[4]={NUF_CONTROL_WAIT_US,NUF_READ_WAIT_US,NUF_WRITE_WAIT_US,NUF_FLUSH_WAIT_US};
 /* The full transfer deadline, clock-stall watchdog and failure retirement
  * are unchanged. READ10, WRITE10 and real SYNCHRONIZE CACHE10 share the fast window. A
  * missing stall callback falls back to the preserved 100us policy. */
 U32 fast=off==0x58&&(r->Opcode==0x28||r->Opcode==0x2A||r->Opcode==0x35)&&!e->ControlWaitLegacy&&e->Ops.StallUs;
 U64 window=fast?NUF_READ_POLL_WINDOW_US:NUF_SPIN_WAIT_US;
 U64 start=e->Ops.ClockUs(e->Ops.Context),last=start,sleepStart=0;U32 same=0,afterSleep=0;
 NUF_WAIT_SAMPLE *sample=NULL;
 if(off==0x58&&e->PerfClock&&e->PerfCommands&&e->PerfCommands<=2){
  sample=&e->PerfWait[e->PerfCommands-1];memset(sample,0,sizeof(*sample));
  sample->StartUs=start;sample->WindowUs=(U32)window;sample->Kind=kind;
 }
 for(U64 n=0;n<4000000ULL;n++){
  U64 now=e->Ops.ClockUs(e->Ops.Context);r->WaitLoops=n+1;
  if(now<last){return fail(e,NufClock);}same=now==last?same+1:0;last=now;
  r->WaitUs=now-start;if(r->WaitUs>e->MaxWaitUs[kind])e->MaxWaitUs[kind]=r->WaitUs;
  if(sample){
   sample->Polls++;
   if(afterSleep){
    U64 elapsed=now-sleepStart;sample->LastWakeUs=now;sample->SleepElapsedUs+=elapsed;
    if(elapsed>sample->MaxSleepUs)sample->MaxSleepUs=elapsed;
    sample->SleepBuckets[waitbucket(elapsed)]++;
   }
  }
  if(!owned(e))return fail(e,NufOwnership);
  if((rd(e,off)&mask)==want){
   if(sample){sample->ClearUs=now;sample->Completed=1;sample->DoneAfterWake=afterSleep;}
   return 1;
  }
  if(sample)sample->LastPendingUs=now;
  afterSleep=0;
  if((rd(e,0x20)&NUF_FATAL_IS)!=0)return fail(e,NufResponse);
  if(r->WaitUs>=budgets[kind]){e->WaitTimeouts++;return fail(e,NufTimeout);}
  if(same>=200000U)return fail(e,NufClock);
  /* Once the clock advances, long waits yield the CPU. A stopped clock
   * switches back to the existing iteration watchdog, not 200000 sleeps.
   * Ownership and fatal status are rechecked after each wake. */
  if(e->Ops.SleepUs&&r->WaitUs>=window&&!same){
   U64 left=budgets[kind]-r->WaitUs;
   if(sample){
    /* Read immediately before the actual wait, not before ownership/MMIO.
     * The next loop timestamps its return before further MMIO. */
    sleepStart=e->Ops.ClockUs(e->Ops.Context);
    if(sleepStart<last)return fail(e,NufClock);
    if(sleepStart>last)same=0;last=sleepStart;
    if(sleepStart-start>=budgets[kind]){e->WaitTimeouts++;return fail(e,NufTimeout);}
    left=budgets[kind]-(sleepStart-start);
    if(!sample->SleepCalls)sample->FirstSleepUs=sleepStart;
    sample->LastSleepUs=sleepStart;sample->SleepCalls++;
    sample->SleepRequestedUs+=left<1000?left:1000;
   }
   e->WaitSleeps++;afterSleep=1;e->Ops.SleepUs(e->Ops.Context,(U32)(left<1000?left:1000));
  }else if(fast&&r->WaitUs<window&&!same){
   U64 left=window-r->WaitUs;
   U32 step=(U32)(left<NUF_READ_POLL_STEP_US?left:NUF_READ_POLL_STEP_US);
   if(sample){sample->StallCalls++;sample->StallRequestedUs+=step;}
   e->Ops.StallUs(e->Ops.Context,step);
  }else e->Ops.Pause(e->Ops.Context);
 }return fail(e,NufClock);}
static int badbyte(NUF_ENGINE *e,U32 off,U8 expected,U8 actual){
 e->Report->GuardOffset=off;e->Report->GuardExpected=expected;e->Report->GuardActual=actual;return fail(e,NufGuard);
}
static int bytecheck(NUF_ENGINE *e,U32 off,U32 len,const U8 *want,U8 fill){
 U32 i=0;const volatile U8 *p=e->Dma+off;
 if(!e->ControlGuard32){
  const U64 pattern=(U64)fill*0x0101010101010101ULL;
  /* Byte prologue and bounded scalar loads preserve exact coverage. Four
   * independent reads per iteration reduce loop dependencies. On mismatch
   * report the first differing byte from values already read: never reread
   * volatile DMA to diagnose a mismatch or cross the requested end. */
  while(i<len&&((size_t)(p+i)&7U)){
   U8 v=p[i],w=want?want[i]:fill;e->GuardCheckBytes++;e->GuardReadOps++;
   if(v!=w)return badbyte(e,off+i,w,v);i++;
  }
#if defined(NUF_NC_RANGES)
  if(!want||!((size_t)(want+i)&7U)){
   U32 words=(len-i)/8;
   if(words){
    U64 captured[2];U32 mismatch=NufNcMatchWords(p+i,want?want+i:NULL,pattern,words,captured);
    /* Four-word blocks are loaded before comparison. Count all actual
     * reads, while the returned index still names the first differing word. */
    U32 readWords=mismatch>=words?words:mismatch<(words&~3U)?(mismatch&~3U)+4:mismatch+1;
    e->GuardCheckBytes+=(U64)readWords*8;e->GuardReadOps+=readWords;
    if(mismatch<words){
     for(U32 lane=0;lane<8;lane++){
      U8 actual=(U8)(captured[0]>>(lane*8)),expected=(U8)(captured[1]>>(lane*8));
      if(actual!=expected)return badbyte(e,off+i+mismatch*8+lane,expected,actual);
     }
    }
    i+=words*8;
   }
  }
#endif
  U32 begin=i;
  for(;len-i>=32;i+=32){
   U64 a=ncguard64(p+i),b=ncguard64(p+i+8),c=ncguard64(p+i+16),d=ncguard64(p+i+24);
   U64 wa=want?wb64(want+i):pattern,wb=want?wb64(want+i+8):pattern;
   U64 wc=want?wb64(want+i+16):pattern,wd=want?wb64(want+i+24):pattern;
   if((a^wa)|(b^wb)|(c^wc)|(d^wd)){
    U64 actual[4]={a,b,c,d},expected[4]={wa,wb,wc,wd};
    e->GuardCheckBytes+=i-begin+32;e->GuardReadOps+=(i-begin)/8+4;
    for(U32 word=0;word<4;word++)for(U32 lane=0;lane<8;lane++){
     U8 v=(U8)(actual[word]>>(8*lane)),w=(U8)(expected[word]>>(8*lane));
     if(v!=w)return badbyte(e,off+i+word*8+lane,w,v);
    }
   }
  }
  for(;len-i>=8;i+=8){
   U64 actual=ncguard64(p+i),expected=want?wb64(want+i):pattern;
   if(actual!=expected){
    e->GuardCheckBytes+=i-begin+8;e->GuardReadOps+=(i-begin)/8+1;
    for(U32 lane=0;lane<8;lane++){
     U8 byte=(U8)(actual>>(8*lane)),w=(U8)(expected>>(8*lane));
     if(byte!=w)return badbyte(e,off+i+lane,w,byte);
    }
   }
  }
  e->GuardCheckBytes+=i-begin;e->GuardReadOps+=(i-begin)/8;
 }
 while(i<len&&((size_t)(p+i)&3U)){U8 v=p[i],w=want?want[i]:fill;e->GuardCheckBytes++;e->GuardReadOps++;
  if(v!=w)return badbyte(e,off+i,w,v);i++;}
 while(len-i>=4){U32 v=ncword(p+i),w=want?wbword(want+i):(U32)fill*0x01010101U;
  e->GuardCheckBytes+=4;e->GuardReadOps++;
  if(v!=w){for(U32 b=0;b<4;b++)if((U8)(v>>(b*8))!=(U8)(w>>(b*8)))
    return badbyte(e,off+i+b,(U8)(w>>(b*8)),(U8)(v>>(b*8)));}i+=4;}
 while(i<len){U8 v=p[i],w=want?want[i]:fill;e->GuardCheckBytes++;e->GuardReadOps++;
  if(v!=w)return badbyte(e,off+i,w,v);i++;}return 1;
}
/* phase: 0 full (admission/lifecycle/legacy), 1 pre, 2 post. Only the
 * inactive payload changes timing; mandatory areas retain exact coverage. */
static int immutable_phase(NUF_ENGINE *e,int completed,U32 phase){
 if((e->GuardPolicy!=NUF_GUARD_FULL&&e->GuardPolicy!=NUF_GUARD_CYCLIC)||
    e->GuardCursor>=NUF_GUARD_PAGES)return fail(e,NufOwnership);
 static const U32 guards[]={0,2,4,21};
 for(U32 n=0;n<4;n++)if(!bytecheck(e,guards[n]*4096,4096,0,0xA5))return 0;
 if(e->DataCapacity>NUF_MAX_TRANSFER||(e->DataCapacity%4096))return fail(e,NufOwnership);
 if(!bytecheck(e,4096,8,e->ExpectedTrd,0)||
   (!completed&&!bytecheck(e,4104,1,e->ExpectedTrd+8,0))||
   !bytecheck(e,4105,23,e->ExpectedTrd+9,0)||!bytecheck(e,4128,4064,0,0)||
   !bytecheck(e,12288,32,e->ExpectedCommand,0)||!bytecheck(e,12320,992,0,0)||
   !bytecheck(e,14336,NUF_PRDT_BYTES,e->ExpectedPrdt,0)||
   !bytecheck(e,14336+NUF_PRDT_BYTES,2048-NUF_PRDT_BYTES,0,0))return 0;
 if(!completed&&!bytecheck(e,13312,1024,0,0))return 0;
 /* DATA_OUT is immutable even after completion. A no-data command has no
  * DMA destination and must leave the entire isolated bounce page untouched. */
 if(e->DataOut){if(!bytecheck(e,20480,e->DataCapacity,e->ExpectedData,0))return 0;}
 else if(e->NoData||!completed){if(!bytecheck(e,20480,e->DataCapacity,0,0xCC))return 0;}
 U32 tail=NUF_MAX_TRANSFER-e->DataCapacity;
 if(!phase){
  e->GuardFullChecks++;
  return bytecheck(e,20480+e->DataCapacity,tail,0,0xCC);
 }
 U32 boundary=tail<NUF_GUARD_BOUNDARY?tail:NUF_GUARD_BOUNDARY;
 U64 start=e->GuardCheckBytes;
 int ok=bytecheck(e,20480+e->DataCapacity,boundary,0,0xCC);
 e->GuardBoundaryBytes+=e->GuardCheckBytes-start;
 if(!ok)return 0;
 if(phase==2){
  U32 page=e->GuardCursor*NUF_BLOCK_BYTES;
  e->GuardCursor=(e->GuardCursor+1U)%NUF_GUARD_PAGES;
  e->GuardSweepSteps++;
  if(page>=e->DataCapacity){
   start=e->GuardCheckBytes;
   ok=bytecheck(e,20480+page,NUF_BLOCK_BYTES,0,0xCC);
   e->GuardSweepBytes+=e->GuardCheckBytes-start;
  }
 }
 return ok;
}
static int immutable(NUF_ENGINE *e,int completed){return immutable_phase(e,completed,0);}
static int submission_guards(NUF_ENGINE *e,int completed,int post,U32 capacity){
 U32 phase=e->GuardPolicy==NUF_GUARD_FULL||!e->RequestPrepared||post==2?0U:post?2U:1U;
 if(!immutable_phase(e,completed,phase))return 0;
 if(post&&!phase&&e->GuardPolicy==NUF_GUARD_CYCLIC){
  e->GuardCursor=(e->GuardCursor+1U)%NUF_GUARD_PAGES;e->GuardSweepSteps++;
 }
 /* Newly active bytes must be checked BEFORE state, response, descriptors or
  * payload stores. Do not erase latent tail corruption with a new WRITE. */
 if(!post&&phase&&capacity>e->DataCapacity){
  U64 start=e->GuardCheckBytes;
  int ok=bytecheck(e,20480+e->DataCapacity,capacity-e->DataCapacity,0,0xCC);
  e->GuardActivateBytes+=e->GuardCheckBytes-start;
  if(!ok)return 0;
 }
 return 1;
}
/* Include activation checks in sampled Guard time. Diagnostic clocks never
 * extend/fail the storage deadline; lifecycle uses the untimed full path. */
static int request_guards(NUF_ENGINE *e,int completed,int post,U32 capacity){
 if(!e->PerfClock)return submission_guards(e,completed,post,capacity);
 U64 begin=e->PerfClock(e->Ops.Context);
 int ok=submission_guards(e,completed,post,capacity);
 U64 end=e->PerfClock(e->Ops.Context);
 if(!begin||end<begin)e->PerfClockError=1;
 else e->PerfGuardTicks+=end-begin;
 return ok;
}
/* The complete pre-reset guard has already compared the DMA descriptor to
 * its independent WB expectation. Only changed words need storing. TRD word1
 * is forced because OCS is the one controller-owned byte in that descriptor.
 * This helper never reads back DMA to manufacture an expected value. */
static U32 descriptor_patch(volatile U8 *dma,U8 *expected,const U8 *next,U32 bytes,U32 forced){
 U32 written=0;
 for(U32 off=0;off<bytes;off+=8){
  if((forced&(1U<<(off/8)))||wb64(expected+off)!=wb64(next+off)){
   dmawrite(dma+off,next+off,8);written+=8;
  }
 }
 memcpy(expected,next,bytes);return written;
}
static int request(NUF_ENGINE *e,U32 op,U32 bytes,U64 lba,U32 tag,const U8 *payload){
 NUF_REPORT *r=e->Report;volatile U8 *dmaTrd=e->Dma+4096,*rsp=e->Dma+13312;
 U8 trd[32],cmd[32];U8 *prd=e->ExpectedPrdt;
 U64 base=e->Config.DmaBase;U32 before,after;
 U32 capacity=bytes?((bytes+4095U)&~4095U):0,entries=capacity/4096;
 int write=op==0x2A,noData=op==0x35;
 if(!NufReadCommandAllowed(op,e->Config.Lun,bytes,lba,tag)&&
   !(e->Config.Lun==0&&tag>=1&&tag<=255&&
     ((write&&NufWriteRangeAllowed(&e->Config,lba,bytes)&&payload)||
      (noData&&(lba==0||NufWriteRangeAllowed(&e->Config,lba,4096))&&bytes==0&&!payload))))return fail(e,NufBadArgument);
 if((!write&&payload)||(write&&lba>e->Config.LastLba))return fail(e,NufBadArgument);
 if(!e->SessionActive||e->Quarantined||r->Quarantined||!e->RequestRetired)return fail(e,NufOwnership);
 if(!idle(e,1,base+4096)||(rd(e,0x20)&(NUF_FATAL_IS|1U)))return fail(e,NufDrift);
 if(r->Issued!=r->Acknowledged)return fail(e,NufOwnership);
 /* Validate mandatory previous-command bytes and every newly active byte
  * BEFORE resetting any of them. Inactive interior uses the selected policy. */
 if(!request_guards(e,e->RequestPrepared!=0,0,capacity))return 0;
 /* UC, page-isolated owned memory: fence is sufficient, no cached alias. */
 U32 oldCapacity=e->DataCapacity,prepared=e->RequestPrepared;
 e->RequestRetired=0;e->RequestPrepared=1;
 e->DataOut=(U32)write;e->NoData=(U32)noData;e->DataCapacity=capacity;
 /* Construct independently in WB memory. The response allocation remains
  * 1024B, but only the 52B consumed by validation/diagnostics needs resetting.
  * Its other bytes were initialized at Open and were already mutable after
  * command completion in PERF4; they are not promoted to valid response data. */
 memset(trd,0,32);memset(cmd,0,32);dmafill(rsp,0,sizeof(r->RawResponse));
 e->RequestResetBytes+=sizeof(r->RawResponse);
 if(write){
  memcpy(e->ExpectedData,payload,bytes);dmawrite(e->Dma+20480,e->ExpectedData,bytes);
  e->RequestResetBytes+=bytes;
 }
 /* READ's active destination is overwritten by the controller and published
  * only after full successful completion/residual validation. Do not poison
  * it first. Scrub only formerly active bytes becoming inactive; the preceding
  * guard checks the previous active DATA_OUT in full. Already inactive bytes
  * are NEVER cleared here, preserving latent faults for sweep/activation. */
 if(oldCapacity>capacity){
  dmafill(e->Dma+20480+capacity,0xCC,oldCapacity-capacity);
  e->RequestResetBytes+=oldCapacity-capacity;
 }
 put32(trd,write?0x13000000:noData?0x11000000:0x15000000);trd[8]=15;put32(trd+16,(U32)(base+12288));
 put32(trd+20,0);put32(trd+24,0x04000400);put32(trd+28,0x08000000U|(entries?(entries+1U)*16U:0));
 /* Preserve the existing ORDERED task attribute (bit0), change only direction. */
 cmd[0]=1;cmd[1]=(U8)(write?0x21:noData?0x01:0x41);cmd[2]=(U8)e->Config.Lun;cmd[3]=(U8)tag;
 cmd[12]=(U8)(bytes>>24);cmd[13]=(U8)(bytes>>16);cmd[14]=(U8)(bytes>>8);cmd[15]=(U8)bytes;
 cmd[16]=(U8)op;if(op==0x28||write||noData){
  cmd[18]=(U8)(lba>>24);cmd[19]=(U8)(lba>>16);cmd[20]=(U8)(lba>>8);cmd[21]=(U8)lba;cmd[23]=(U8)((bytes/4096)>>8);cmd[24]=(U8)(bytes/4096);}
 /* N976N inherited HCI uses 16-byte PRDs and byte-unit length including
  * one zero 16-byte suffix (sboot dfd30); not the reference FMP 128-byte stride.
  * Capacity keeps a full isolated 4KiB DMA destination for controller padding. */
 if(!prepared||oldCapacity!=capacity){
  memset(prd,0,NUF_PRDT_BYTES);
  for(U32 n=0;n<entries;n++){put32(prd+n*16,(U32)(base+20480+n*4096));
   put32(prd+n*16+4,0);put32(prd+n*16+12,4095);}
  U32 span=((oldCapacity>capacity?oldCapacity:capacity)/4096+1U)*16U;
  /* Including the Samsung zero suffix; untouched remaining bytes were
   * verified before reuse and remain independently expected zero. */
  dmawrite(e->Dma+14336,prd,span);e->RequestResetBytes+=span;
 }
 e->RequestResetBytes+=descriptor_patch(e->Dma+4096,e->ExpectedTrd,trd,32,2U);
 e->RequestResetBytes+=descriptor_patch(e->Dma+12288,e->ExpectedCommand,cmd,32,0);
 /* The retired slot was checked above before any reset. While software owns
  * it, these bounded descriptor/payload stores cannot make controller DMA
  * active: only the later doorbell transfers ownership. Do not rescan every
  * NC guard/padding/payload byte immediately after our own stores. Keep the
  * fence and final idle/ownership gate, then check the entire immutable span
  * after DMA completion before publishing data or acknowledging this slot.
  * The pre-reset and stop/restart scans still preserve corruption evidence. */
 e->Ops.Fence(e->Ops.Context);
 if(!idle(e,1,base+4096)||(rd(e,0x20)&(NUF_FATAL_IS|1U)))return fail(e,NufDrift);
 wr(e,0x1140,e->Config.Nexus|1U);if(rd(e,0x1140)!=(e->Config.Nexus|1U))return fail(e,NufDrift);
 r->Opcode=op;r->Tag=tag;r->Issued++;
 U32 command=e->PerfCommands;
 if(e->PerfClock){
  if(command<2)e->PerfIssue[command]=e->PerfClock(e->Ops.Context);
  e->PerfCommands++;
 }
 wr(e,0x58,1);
 if(!waitreg(e,0x58,~0U,0)){snapshot(e);r->Quarantined=e->Quarantined=1;return 0;}
 if(e->PerfClock&&command<2)e->PerfDone[command]=e->PerfClock(e->Ops.Context);
 e->Ops.Fence(e->Ops.Context);snapshot(e);
 if(!idle(e,1,base+4096)||!request_guards(e,1,prepared?1:2,capacity)){r->Quarantined=1;return fail(e,r->Reason?r->Reason:NufDrift);}
 r->Ocs=dmaTrd[8];dmacopy(r->RawResponse,rsp,sizeof(r->RawResponse));
 const U8 *response=r->RawResponse; /* One captured response for both evidence and decisions. */
 r->Response=response[6];r->ScsiStatus=response[7];
 r->Residual=be32(response+12);r->SenseBytes=((U32)response[32]<<8)|response[33];
 if(r->Ocs||response[0]!=0x21||response[1]||response[2]!=e->Config.Lun||response[3]!=tag||
  (response[4]&15U)||r->Response||r->ScsiStatus||response[8]||response[10]||response[11]||r->Residual||r->SenseBytes){
  r->Quarantined=1;return fail(e,NufResponse);}
 before=rd(e,0x20);if((before&NUF_FATAL_IS)||!(before&1U)){r->Quarantined=1;return fail(e,NufAck);}
 wr(e,0x20,1);after=rd(e,0x20);
 if((after&(NUF_FATAL_IS|1U))||((after&(before&~1U))!=(before&~1U))||!idle(e,1,base+4096)){
  r->Quarantined=1;return fail(e,NufAck);}
 r->Acknowledged++;e->RequestRetired=1;return 1;}
static int retire(NUF_ENGINE *e,int wait,int restartable){NUF_REPORT *r=e->Report;
 /* A failed Restart may quarantine before changing our list registers. That
  * is not permission to release the mapped arena through the no-change path. */
 if(e->Quarantined||r->Quarantined){r->Quarantined=e->Quarantined=1;r->Retired=0;r->CleanupReason=NufCleanup;return 0;}
 if(!e->Changed){
  /* A retained stopped arena may have changed since Stop. Inspect only after
   * confirming the old list remains idle and the lease is still owned. */
  if(e->DmaInitialized&&e->Stopped){
   if(!e->RequestRetired||r->Issued!=r->Acknowledged||
      !idle(e,0,e->Config.OldTrlBase)||(rd(e,0x20)&(NUF_FATAL_IS|1U))||
      rd(e,0x1140)!=e->Config.Nexus){
    r->Quarantined=e->Quarantined=1;r->Retired=0;r->CleanupReason=NufCleanup;return 0;
   }
   if(!immutable(e,e->RequestPrepared!=0)){r->Retired=0;r->CleanupReason=NufCleanup;return 0;}
  }
  r->Retired=1;return 1;
 }
 if(e->Quarantined||r->Quarantined||(!wait&&!e->RequestRetired)||!owned(e)||r->Issued!=r->Acknowledged||
   !idle(e,e->Running,e->Config.DmaBase+4096)||(rd(e,0x20)&(NUF_FATAL_IS|1U))){
  r->Quarantined=e->Quarantined=1;r->CleanupReason=NufCleanup;return 0;}
 if(e->DmaInitialized&&!immutable(e,e->RequestPrepared!=0)){r->CleanupReason=NufCleanup;return 0;}
 /* Stop is invoked only after the adapter drained all requests. No poll or
  * time callback is permitted in its DIRQL path. A stuck RUN retains DMA. */
 wr(e,0x60,0);if(wait?!waitreg(e,0x60,~0U,0):rd(e,0x60)!=0){
  r->Quarantined=e->Quarantined=1;r->CleanupReason=NufCleanup;return 0;}
 e->Running=0;if(!idle(e,0,e->Config.DmaBase+4096)){r->Quarantined=e->Quarantined=1;r->CleanupReason=NufCleanup;return 0;}
 wr(e,0x1140,e->Config.Nexus);wr(e,0x50,(U32)e->Config.OldTrlBase);wr(e,0x54,(U32)(e->Config.OldTrlBase>>32));
 if(!idle(e,0,e->Config.OldTrlBase)||rd(e,0x1140)!=e->Config.Nexus){r->Quarantined=e->Quarantined=1;r->CleanupReason=NufCleanup;return 0;}
 e->Changed=e->SessionActive=0;e->Stopped=(U32)restartable;e->Closed=(U32)!restartable;
 e->SessionCloses++;r->Retired=1;return 1;}
static int valid(NUF_ENGINE *e){return e&&e->Report&&e->Dma&&e->Ops.Read&&e->Ops.Write&&e->Ops.ClockUs&&
 e->Ops.Fence&&e->Ops.Pause&&e->Ops.Owned;}
int NufSessionOpen(NUF_ENGINE *e){NUF_REPORT *r;NUF_CONFIG *c;
 if(!valid(e))return 0;
 r=e->Report;c=&e->Config;r->Stage=NufStagePrepare;
 /* Zero-initialized callers retain full coverage. Unknown policy/cursor is
  * rejected before DMA initialization or controller writes. */
 if(!e->GuardPolicy&&!e->DmaInitialized)e->GuardPolicy=NUF_GUARD_FULL;
 if((e->GuardPolicy!=NUF_GUARD_FULL&&e->GuardPolicy!=NUF_GUARD_CYCLIC)||
    e->GuardCursor>=NUF_GUARD_PAGES)return fail(e,NufOwnership);
 r->DmaBase=c->DmaBase;r->OldTrlBase=c->OldTrlBase;r->ExpectedLastLba=c->LastLba;r->Lun=c->Lun;
 if(!c->Baseline||c->BlockBytes!=4096||c->Lun!=0||c->LastLba==0||c->LastLba>=0xFFFFFFFFULL||
  c->DmaBase<0x92001000ULL||c->DmaBase>0x95FDE000ULL-NUF_DMA_BYTES||
  (c->DmaBase&4095)||c->OldTrlBase<0x92001000ULL||c->OldTrlBase>0x95FDE000ULL-4096||
  (c->OldTrlBase&4095)||r->Issued||r->Acknowledged||r->Retired||e->Changed||e->Running||
  e->SessionActive||e->DmaInitialized||e->Quarantined||r->Quarantined||e->Closed||e->Stopped||
  (c->OldTrlBase<c->DmaBase+NUF_DMA_BYTES&&c->DmaBase<c->OldTrlBase+4096)||
  c->Tx!=12||c->Rx!=12||c->Reorder!=10||c->Iacr!=0){return fail(e,NufBadArgument);}
 if(!idle(e,0,c->OldTrlBase)||(rd(e,0x20)&(NUF_FATAL_IS|1U))||rd(e,0x1140)!=c->Nexus)return fail(e,NufDrift);
 r->ExpectedCrc=NufCrc32(c->Baseline,4096);
 /* Every arena byte is initialized exactly once. Subsequent requests retain
  * guards and unused descriptor space and check them before any reuse. */
 for(U32 p=0;p<22;p++)dmafill(e->Dma+p*4096,
  (U8)((p==0||p==2||p==4||p==21)?0xA5:p>=5?0xCC:0),4096);
 e->DataCapacity=0;
 e->DmaInitBytes+=NUF_DMA_BYTES;e->DmaInitialized=1;e->DataOut=e->NoData=0;
 memset(e->ExpectedTrd,0,sizeof(e->ExpectedTrd));memset(e->ExpectedCommand,0,sizeof(e->ExpectedCommand));
 memset(e->ExpectedPrdt,0,sizeof(e->ExpectedPrdt));e->RequestPrepared=0;e->RequestRetired=1;
 e->Ops.Fence(e->Ops.Context);
 if(!idle(e,0,c->OldTrlBase)||(rd(e,0x20)&(NUF_FATAL_IS|1U)))return fail(e,NufDrift);
 e->Changed=1;e->ListPrograms++;wr(e,0x50,(U32)(c->DmaBase+4096));wr(e,0x54,0);
 if(!idle(e,0,c->DmaBase+4096)){r->Quarantined=1;return fail(e,NufDrift);}
 e->Running=1;wr(e,0x60,1);if(!waitreg(e,0x60,~0U,1)){r->Quarantined=e->Quarantined=1;return 0;}
 e->SessionActive=1;e->SessionOpens++;
 return 1;
}
int NufRequestRetired(const NUF_ENGINE *e){return e&&e->Report&&e->DmaInitialized&&
 e->RequestRetired&&!e->Quarantined&&!e->Report->Quarantined&&!e->Report->CleanupReason;}
int NufSessionClose(NUF_ENGINE *e){
 if(!valid(e))return 0;int ok=retire(e,1,0);
 if(ok){e->SessionActive=e->Stopped=0;e->Closed=1;}return ok;
}
int NufSessionStop(NUF_ENGINE *e){
 if(!valid(e)||!e->SessionActive)return 0;
 int ok=retire(e,0,1);if(ok)e->SessionStops++;return ok;
}
int NufSessionRestart(NUF_ENGINE *e){
 if(!valid(e))return 0;NUF_REPORT *r=e->Report;NUF_CONFIG *c=&e->Config;
 if(!e->Stopped||e->Closed||e->SessionActive||!e->DmaInitialized||e->Changed||e->Running||
    !NufRequestRetired(e)||r->Issued!=r->Acknowledged)return fail(e,NufOwnership);
 r->Retired=0;
 if(!idle(e,0,c->OldTrlBase)||(rd(e,0x20)&(NUF_FATAL_IS|1U))||rd(e,0x1140)!=c->Nexus){
  r->Quarantined=1;return fail(e,NufDrift);}
 if(!immutable(e,e->RequestPrepared!=0))return 0;
 e->Changed=1;e->Stopped=0;r->Retired=0;e->ListPrograms++;
 wr(e,0x50,(U32)(c->DmaBase+4096));wr(e,0x54,0);
 if(!idle(e,0,c->DmaBase+4096)){r->Quarantined=1;return fail(e,NufDrift);}
 e->Running=1;wr(e,0x60,1);
 if(rd(e,0x60)!=1||!idle(e,1,c->DmaBase+4096)||(rd(e,0x20)&(NUF_FATAL_IS|1U))){
  r->Quarantined=1;return fail(e,NufDrift);}
 e->SessionActive=1;e->SessionRestarts++;return 1;
}
int NufRun(NUF_ENGINE *e){int ok=0,standalone;NUF_REPORT *r;NUF_CONFIG *c;
 if(!valid(e))return 0;r=e->Report;c=&e->Config;
 standalone=!e->SessionActive;if(standalone&&!NufSessionOpen(e))goto done;
 r->Stage=NufStageCapacity;if(!request(e,0x25,8,0,1,NULL))goto done;
 r->LastLba=be32(e->Dma+20480);r->BlockBytes=be32(e->Dma+20484);
 if(r->LastLba!=c->LastLba||r->BlockBytes!=c->BlockBytes){fail(e,NufCapacity);goto done;}r->CapacityChecked=1;
 r->Stage=NufStageRead;if(!request(e,0x28,4096,0,2,NULL))goto done;r->ReadChecked=1;
 r->Stage=NufStageCompare;r->ReadCrc=dmacrc(e->Dma+20480,4096);
 for(U32 i=0;i<4096;i++)if(e->Dma[20480+i]!=c->Baseline[i]){
  r->FirstMismatch=i;r->ExpectedByte=c->Baseline[i];r->ActualByte=e->Dma[20480+i];fail(e,NufCompare);goto done;}
 r->Compared=1;ok=1;
done:if(standalone){r->Stage=NufStageRetire;if(!NufSessionClose(e)){if(!r->FirstReason)fail(e,NufCleanup);ok=0;}}
 if(ok){r->Stage=NufStageComplete;r->Reason=NufOk;}return ok;}

/* One bounded OS transfer through the guarded low bounce arena. The caller maps
 * the OS buffer for CPU access; it is never used as a hardware DMA address.
 * A failed submission is terminal/quarantined, never retried or reconstructed. */
int NufReadBlock(NUF_ENGINE *e,U64 lba,U32 tag,U8 *output,U32 bytes){
 int ok=0,standalone;NUF_REPORT *r;
 if(!valid(e))return 0;r=e->Report;
 if(!output||!NufReadCommandAllowed(0x28,e->Config.Lun,bytes,lba,tag)||
    lba>e->Config.LastLba||bytes/4096-1>e->Config.LastLba-lba)return fail(e,NufBadArgument);
 standalone=!e->SessionActive;if(standalone&&!NufSessionOpen(e))goto done;
 r->Stage=NufStageRead;if(!request(e,0x28,bytes,lba,tag,NULL))goto done;
 r->ReadChecked=1;ok=1;
 done:if(standalone){r->Stage=NufStageRetire;if(!NufSessionClose(e)){if(!r->FirstReason)fail(e,NufCleanup);ok=0;}}
 if(ok){dmacopy(output,e->Dma+20480,bytes);r->Stage=NufStageComplete;r->Reason=NufOk;}
 return ok;
}

/* Each ordinary write is one owned transfer of at most 64KiB. Standard flush policy is the
 * adapter's responsibility. No high or OS buffer is ever used as a DMA alias. */
static int write_command(NUF_ENGINE *e,U64 lba,U32 tag,const U8 *payload,U32 bytes,int flush){
 int ok=0,standalone;NUF_REPORT *r;if(!valid(e))return 0;r=e->Report;
 if(tag<1||tag>255||e->Config.Lun||
    (flush?(payload!=NULL||bytes!=0||lba!=0):(!payload||!NufWriteRangeAllowed(&e->Config,lba,bytes))))return fail(e,NufBadArgument);
 standalone=!e->SessionActive;if(standalone&&!NufSessionOpen(e))goto done;r->Stage=flush?NufStageFlush:NufStageWrite;
 if(!request(e,flush?0x35:0x2A,bytes,lba,tag,payload))goto done;ok=1;
 done:if(standalone){r->Stage=NufStageRetire;if(!NufSessionClose(e)){if(!r->FirstReason)fail(e,NufCleanup);ok=0;}}
 if(ok){r->Stage=NufStageComplete;r->Reason=NufOk;}return ok;
}
int NufWriteBlock(NUF_ENGINE *e,U64 lba,U32 tag,const U8 *payload,U32 bytes){return write_command(e,lba,tag,payload,bytes,0);}
/* Standard flush uses IMMED=0, LBA0/count0: synchronize the whole admitted LUN. */
int NufFlushCache(NUF_ENGINE *e,U32 tag){return write_command(e,0,tag,NULL,0,1);}
