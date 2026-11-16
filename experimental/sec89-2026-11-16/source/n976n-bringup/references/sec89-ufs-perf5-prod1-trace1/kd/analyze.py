#!/usr/bin/env python3
"""Decode exact TRACE1 CPU-RAM snapshots; never accesses a target or debugger."""
import argparse,json,struct,os,stat
from pathlib import Path
SIZE=27160;CAP=128;MAX=(1<<64)-1
KINDS=['READ4K','READlarge','WRITE4K','WRITElarge','FUA4K','FUAlarge','FLUSH']
BIN='Attempts Selected Valid Failed Invalid Bytes TotalTicks QueueTicks PrepareTicks DeviceTicks BetweenTicks FinishTicks GuardPreTicks GuardPostTicks ReadCopyTicks WriteCopyTicks GuardBytes GuardLoads MaxTotalTicks MaxDeviceTicks SleepCalls SleepRequestedUs SleepElapsedUs WaitObservedUs'.split()
HEADER='Generation Frequency InstanceQpc InstanceSystemTime Attempts Selected Published Overwritten InvalidTimings GuardBytes GuardLoads ResetBytes SweepSteps WaitSleeps WaitTimeouts MaxWaitUs0 MaxWaitUs1 MaxWaitUs2 MaxWaitUs3'.split()
REC64='Sequence T0 Worker T1a T1b T2a T2b T3 GuardPreTicks GuardPostTicks ReadCopyTicks WriteCopyTicks GuardBytes GuardLoads SleepCalls SleepRequestedUs SleepElapsedUs WaitObservedUs Lba'.split()
REC32='Kind Opcode Bytes Flags SrbStatus ScsiStatus Reason Commands CursorBefore CursorAfter Reserved0 Reserved1'.split()
def need(ok,why):
 if not ok:raise ValueError(why)
def total(xs):
 n=sum(xs);need(n<=MAX,'Counter sum overflow');return n
def decode(data):
 need(len(data)==SIZE,'Exact 27160-byte snapshot required; partial reads rejected')
 h=struct.unpack_from('<Q6I',data)
 need(h==(0x314543415254554e,1,SIZE,0x00590206,200,CAP,65),'Wrong TRACE1 identity/ABI')
 s=dict(zip(HEADER,struct.unpack_from('<19Q',data,32)))
 tail=struct.unpack_from('<8I',data,184);s.update(zip(['RecordCount','NextRecord','LastStop','LastQuarantined','LastSessionState'],tail[:5]))
 need(not any(tail[5:]) and not s['Generation']&1,'Reserved/active-generation snapshot')
 need(s['RecordCount']==min(s['Published'],CAP) and s['NextRecord']==s['Published']%CAP,'Ring shape differs')
 need(s['Selected']==s['Published']<=s['Attempts'] and s['Overwritten']==s['Published']-s['RecordCount'],'Ring accounting differs')
 bins=[]
 for k in range(7):
  b=dict(zip(BIN,struct.unpack_from('<24Q',data,216+k*192)))
  need(total(b[n] for n in ['Valid','Failed','Invalid'])==b['Selected']<=b['Attempts'],'Sample classes differ')
  need(total(b[n] for n in ['QueueTicks','PrepareTicks','DeviceTicks','BetweenTicks','FinishTicks'])==b['TotalTicks'],'Phase sum differs')
  need(total(b[n] for n in ['GuardPreTicks','GuardPostTicks','ReadCopyTicks','WriteCopyTicks','DeviceTicks'])<=b['TotalTicks'],'Subset cost exceeds total')
  bins.append(b)
 need(total(b['Attempts'] for b in bins)==s['Attempts'] and total(b['Selected'] for b in bins)==s['Selected'],'Whole/bin counters differ')
 records=[];previous=0
 for i in range(s['RecordCount']):
  at=1560+200*((s['NextRecord']+CAP-s['RecordCount']+i)%CAP)
  q=struct.unpack_from('<19Q12I',data,at);v=dict(zip(REC64+REC32,q))
  need(previous<v['Sequence']<=s['Attempts'] and v['Kind']<7 and v['Commands']<=2,'Record bounds/order differs')
  previous=v['Sequence'];flags=v['Flags']
  need(not flags&~15 and flags&7 and bool(flags&8)==(v['Commands']==2) and not v['Reserved0'] and not v['Reserved1'],'Record flags/reserved differ')
  if flags&1:
   need(not flags&6 and s['Frequency'] and v['T0'] and v['Commands']==(2 if v['Kind'] in (4,5) else 1),'Valid timing classification differs')
   times=[v['T0'],v['Worker'],v['T1a'],v['T2a']]+([v['T1b'],v['T2b']] if v['Commands']==2 else [])+[v['T3']]
   need(times==sorted(times),'Timestamps out of order')
  records.append(v)
 s['bins']=bins;s['records']=records;return s
def read(path):
 with Path(path).open('rb') as f:
  need(stat.S_ISREG(os.fstat(f.fileno()).st_mode),'Regular snapshot file required')
  return decode(f.read(SIZE+1))
def compare(a,b):
 need(a['InstanceQpc'] and a['InstanceSystemTime'] and a['Frequency'],'No established instance/clock')
 for n in ['InstanceQpc','InstanceSystemTime','Frequency']:need(a[n]==b[n],'NOT COMPARABLE: '+n)
 for n in HEADER:
  if n not in ['InstanceQpc','InstanceSystemTime','Frequency']:need(b[n]>=a[n],'NOT COMPARABLE: counter reset '+n)
 for x,y in zip(a['bins'],b['bins']):
  for n in BIN:need(y[n]>=x[n],'NOT COMPARABLE: bin counter reset '+n)
 return [{n:y[n]-x[n] for n in BIN} for x,y in zip(a['bins'],b['bins'])]
def report(b,a=None):
 bins=compare(a,b) if a else b['bins'];result={'mode':'interval' if a else 'cumulative','instance':[b['InstanceQpc'],b['InstanceSystemTime']],
 'frequency':b['Frequency'],'sample_period':65,'published_cumulative':b['Published'],'retained':b['RecordCount'],'overwritten_cumulative':b['Overwritten'],
 'whole':{n:b[n]-(a[n] if a else 0) for n in ['Attempts','Selected','GuardBytes','GuardLoads','ResetBytes','SweepSteps','WaitSleeps','WaitTimeouts','InvalidTimings']},'kinds':{}}
 for name,row in zip(KINDS,bins):
  result['kinds'][name]={n:row[n] for n in ['Attempts','Selected','Valid','Failed','Invalid','Bytes','GuardBytes','GuardLoads','SleepCalls','SleepRequestedUs','SleepElapsedUs','WaitObservedUs']}
  result['kinds'][name]['sampled_mean_ms']={n:row[n]*1000/b['Frequency']/row['Valid'] if row['Valid'] and b['Frequency'] else None for n in BIN[6:16]}
 # Do not subtract maxima: an interval maximum cannot be recovered from cumulative maxima.
 result['limitations']=['Means cover valid 1/65 per-kind samples; failures/invalid separately counted.',
 'Guard/copy overlap queue/prepare/between/finish; do not add twice.',
 'DeviceTicks includes polling, sleeps and scheduling, not pure hardware latency.',
 'T0 is admitted StartIo; T3 is before telemetry publication/RequestComplete. Windows outside this span is excluded.',
 '128-record ring overwrites; no p99 claim. Instance identity is diagnostic, not a cryptographic boot ID.']
 return result
def text(r):
 lines=[f"TRACE1 {r['mode']} / sample 1/65 / retained {r['retained']} / overwritten {r['overwritten_cumulative']}",
 'kind attempts selected valid failed invalid | total queue prepare device-observed between finish | guard-pre guard-post read-copy write-copy (sampled ms)']
 for name,v in r['kinds'].items():
  means=v['sampled_mean_ms'];lines.append(name+' '+' '.join(str(v[n]) for n in ['Attempts','Selected','Valid','Failed','Invalid'])+' | '+' '.join('NA' if n is None else f'{n:.6f}' for n in means.values()))
 lines+=['Whole interval/cumulative: '+json.dumps(r['whole'])]+r['limitations'];return '\n'.join(lines)+'\n'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('after');p.add_argument('--before');p.add_argument('--json',action='store_true');a=p.parse_args()
 try:r=report(read(a.after),read(a.before) if a.before else None);print(json.dumps(r,indent=2) if a.json else text(r),end='\n' if a.json else '')
 except (ValueError,OSError) as e:p.exit(2,'STOP: '+str(e)+'\n')
if __name__=='__main__':main()
