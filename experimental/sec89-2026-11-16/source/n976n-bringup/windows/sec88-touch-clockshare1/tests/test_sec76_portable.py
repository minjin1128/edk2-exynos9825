#!/usr/bin/env python3
"""SEC76 production transport, handoff, Windows runtime and HID targeted checks."""
import argparse, hashlib, importlib.util, json, os, subprocess, tempfile, time
from pathlib import Path

def main():
 a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);a.add_argument('--suites',nargs='+',choices=('runtime','hsi','command','demo','diagnostic','queue'),default=['runtime','hsi','command','demo','diagnostic','queue']);args=a.parse_args()
 if args.output.exists():raise SystemExit('new evidence path required')
 scratch=os.environ.get('N976N_RAM_SCRATCH_PATH')
 if not scratch or not Path(scratch).is_dir():raise SystemExit('managed RAM required')
 port=Path(__file__).resolve().parents[1];project=port.parents[1]
 dependency_names=['N976nDemoRuntime.c','N976nDemoRuntime.h','N976nDemoLifecycle.h','N976nDemoStartup.h','N976nHsiWaitShape.h','N976nDemoContract.c','N976nDemoContract.h','N976nDemoDiagnostic.h','N976nTouchHandoff.h','N976nHsi2c.c','N976nHsi2c.h','N976nResources.h','Y771Event.c','Y771Event.h','Device.c','Device.h','tests/runtime_cases.c','tests/hsi_cases.c','tests/command_cases.c','tests/runtime_mocks/wdf.h','tests/runtime_mocks/ntddk.h','tests/demo_fixture.h','tests/demo_cases.c','tests/diagnostic_cases.c','tests/portable_cases.c','N976nStartup.c','N976nStartup.h','N976nTouchDemo.c','Build-Sec76.ps1','tests/poll_mock.inc']
 dependency_names += ['tests/tail_timeout_cases.inc', 'tests/tail_timeout_fixture.inc','ClockShare.h','ClockShare.c','tests/runtime_mocks/clockshare_mocks.inc']
 files=[port/n for n in dependency_names]+[Path(__file__).resolve()]
 baseline_files=[project/'windows/sec76-fix1'/n for n in ('N976nDemoContract.c','N976nDemoContract.h','N976nTouchHandoff.h','N976nHsi2c.h')]
 def baseline_bindings():return {str(p.relative_to(project)):hashlib.sha256(p.read_bytes()).hexdigest() for p in baseline_files}
 baseline_before=baseline_bindings()
 exp1=project/'windows/sec76-exp8'
 exp1_names=['N976nDemoRuntime.c','N976nDemoRuntime.h','N976nDemoLifecycle.h','N976nDemoStartup.h','N976nDemoContract.c','N976nDemoContract.h','N976nDemoDiagnostic.h','N976nTouchHandoff.h','N976nHsi2c.c','N976nHsi2c.h','N976nResources.h','Y771Event.c','Y771Event.h','Device.c']
 def exp1_bindings():return {str((exp1/n).relative_to(project)):hashlib.sha256((exp1/n).read_bytes()).hexdigest() for n in exp1_names}
 exp1_before=exp1_bindings()
 def bindings():return {str(p.relative_to(port)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
 before=bindings();started=time.monotonic();out={'milestone':'SEC88 TOUCH CLOCKSHARE1','passed':False,'suites':{},'checks':[],
 'source_sha256':before,'baseline_sources_sha256':baseline_before,'preserved_fix2_sources_sha256':{str((project/'windows/sec76-fix2'/n).relative_to(project)):hashlib.sha256((project/'windows/sec76-fix2'/n).read_bytes()).hexdigest() for n in ('N976nDemoRuntime.c','N976nDemoRuntime.h','Device.c','Device.h','N976nDemoContract.c','N976nHsi2c.c')},'hardware_verified':False,'complete_windows_path_verified':False,
 'omitted':['Physical MMIO/clock/power/IRQ behavior','Real Windows PnP/HID scheduling and cancellation','Driver installation/signing/trust/WIM/phone writes','Full historical regression']}
 out['preserved_exp8_sources_sha256']=exp1_before
 out['intentional_change']='Only exact TOP clock observation memory becomes shared; RX1 receive/recovery algorithms unchanged.'
 out['omitted'].append('EXP8 legacy equivalence replay: engine intentionally differs; fresh safety fixtures retained')
 try:
  old=project/'windows/sec74/tests/test_sec74_portable.py'
  spec=importlib.util.spec_from_file_location('sec74_helpers',old);helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
  source=(port/'Device.c').read_text();header=(port/'Device.h').read_text()
  out['descriptor']=helpers.descriptor_contract(source)
  for name in ('OnPrepareHardware','OnD0Entry'):
   assert 'STATUS_NOT_SUPPORTED' not in helpers.no_comments(helpers.function(source,name))
  exitbody=helpers.no_comments(helpers.function(source,'OnD0Exit'))
  assert exitbody.index('WdfTimerStop(C->PollTimer,TRUE)')<exitbody.index('N976nDemoCallback')<exitbody.index('N976nDemoStop')
  releasebody=helpers.no_comments(helpers.function(source,'OnReleaseHardware'))
  assert releasebody.index('WdfTimerStop(C->PollTimer,TRUE)')<releasebody.index('N976nDemoCallback')<releasebody.index('N976nDemoStop')
  assert 'WdfIoQueuePurgeSynchronously(C->ManualQueue)' in exitbody
  assert 'OnInterruptIsr(' not in source and 'SpbDeviceWriteRead(' not in source
  assert 'ACPI\\NNTC0076' in (port/'N976nY771Touch.inf').read_text()
  startup=(port/'N976nStartup.c').read_text();builder=(port/'Build-Sec76.ps1').read_text();runtime=(port/'N976nDemoRuntime.c').read_text()
  assert 'Header[]="N976N-SEC76-EXP9-SHA256\\n"' in startup and "@('N976N-SEC76-EXP9-SHA256')" in builder
  assert 'strstr(Bad,"EXP9")' in startup and "Old[3]='8'" in startup
  assert "'demo-generated-package-contract'" in builder and 'N976nStartupVerifyOwnPackage()' in (port/'N976nTouchDemo.c').read_text()
  assert 'R->Io.NowUs=HsiNowUs;' in runtime and 'KeQueryInterruptTimePrecise(&Qpc)/10' in runtime
  assert 'R->Startup.ElapsedUs=NowUs(R)-Start;' in runtime and 'return KeQueryInterruptTime()/10;' in runtime
  out['checks']+=['EXP9_generated_manifest_parser_header_and_actual_package_check_bound','HSI_precise_callback_and_unchanged_startup_clock_separate']
  contract=(port/'N976nDemoContract.h').read_text();handoff=(port/'N976nTouchHandoff.h').read_text()
  assert 'MAP_COUNT 7U' in contract and 'N976nMapHandoff=5, N976nMapAlive=6' in contract
  assert 'HANDOFF_VERSION 2U' in handoff and 'Gpa1Con, Gpa1Pull, Gpa1EintMask, Gpa1Reserved' in handoff
  assert handoff==(project/'edk2/sec76-exp9/N976nPlatformPkg/Include/N976nTouchHandoff.h').read_text(),'producer/consumer handoff differ'
  assert 'LifeBind(R,NvsAddress)' in runtime and 'if(I==N976nMapHandoff)NvsAddress=Base' in runtime
  readmap=helpers.no_comments(runtime[runtime.index('static int ReadMap('):runtime.index('static int ReadHsi(')])
  assert 'M==N976nMapHandoff' in readmap and 'M==N976nMapAlive&&O!=0x20&&O!=0x24&&O!=0x28&&O!=0x904' in readmap
  poll=helpers.no_comments(helpers.function(source,'N976nServiceTouchEvents'))
  assert poll.count('N976nDemoEventReady(')==1 and poll.index('N976nDemoEventReady(')<poll.index('N976nDemoReadEvent(')<poll.index('N976nDemoReadTail(')
  assert 'if(!NT_SUCCESS(Status)||!Ready)break;' in poll
  out['checks']+=['EXP9_exact_shared_V2_RO_Alive6_NVS5_contract','EXP9_ReadMap_fixed_Alive_offsets_no_NVS_device_alias','EXP9_one_ready_gate_before_new60_not61_or_retry','EXP9_explicit_NVS_address_survives_appended_resource']
  out['checks']+=['HID_descriptor64bytes10contacts4095range','actual_prepare_D0_activate_only_runtime_adapter','timer_join_precedes_transport_cleanup','HID_pending_requests_purged_on_D0_exit','single_private_transport_no_old_SPB_ISR','physical_ACPI_HID_binding']
  with tempfile.TemporaryDirectory(prefix='sec76-',dir=scratch) as td:
   t=Path(td)
   suites=[('hsi',['N976nHsi2c.c'],[]),('command',['N976nHsi2c.c'],[]),('demo',['N976nDemoContract.c'],[]),('runtime',['N976nDemoRuntime.c','N976nDemoContract.c','N976nHsi2c.c','Y771Event.c','ClockShare.c'],['-I',str(port/'tests/runtime_mocks')])]
   baseline=project/'windows/sec76-fix1/N976nDemoContract.c'
   (t/'baseline.c').write_text('#define N976nDemoCrc BaselineCrc\n#define N976nDemoValidateHandoff BaselineValidate\n#define N976nDemoFresh BaselineFresh\n#include '+json.dumps(str(baseline))+'\n')
   suites.append(('diagnostic',['N976nDemoContract.c'],[str(t/'baseline.c')]))
   bodies={n:helpers.function(source,n) for n in helpers.FUNCTIONS}
   out['extracted_production_functions_sha256']={n:hashlib.sha256(s.encode()).hexdigest() for n,s in bodies.items()}
   structs=header[header.index('typedef struct __declspec(align(2))'):header.index('DRIVER_INITIALIZE')]
   context=header[header.index('    S6SY761_CONTACT_STATE   Contacts['):header.index('    PVOID PoFxPowerSettingCallbackHandle1;')]
   packets={'sec71_first':'448CAA550F3A2102A500000000000000','sec71_last':'84DD94B40A0A260204A3000000000000','sec72_first_synthetic':'442124EB'+'00'*12,'sec72_last_synthetic':'C4995BB3'+'00'*12}
   fixture=''.join('static const uint8_t '+n+'[16]={'+','.join('0x'+v[i:i+2] for i in range(0,32,2))+'};\n' for n,v in packets.items())
   runtime_helpers={
    'LifeInc':runtime[runtime.index('static VOID LifeInc('):runtime.index('ULONG N976nDemoLifecycleCrc(')].strip(),
    'N976nDemoValidatedBatch':runtime[runtime.index('VOID N976nDemoValidatedBatch('):runtime.index('NTSTATUS N976nDemoClearEvents(')].strip()}
   out['actual_batch_helpers_sha256']={n:hashlib.sha256(b.encode()).hexdigest() for n,b in runtime_helpers.items()}
   pollbody=helpers.function(source,'N976nServiceTouchEvents')+'\n'+helpers.function(source,'N976nPollTimer')
   out['actual_poll_timer_sha256']=hashlib.sha256(pollbody.encode()).hexdigest()
   prototypes='\n'.join(b[:b.index('{')].rstrip()+';' for b in bodies.values())
   c=helpers.PREFIX.replace('delay==20','delay==20||delay==1')+(port/'tests/poll_mock.inc').read_text()+structs+'typedef struct{WDFQUEUE ManualQueue;WDFWAITLOCK InputLock;POLL_RUNTIME Runtime;WDFTIMER PollTimer;ULONGLONG LastDiagnosticTick;\n'+context+'}DEVICE_CONTEXT,*PDEVICE_CONTEXT;\n#define GetDeviceContext(d) ((PDEVICE_CONTEXT)(d))\n'+fixture+prototypes+'\n'+'\n'.join(bodies.values())+'\n'+'\n'.join(runtime_helpers.values())+'\n'+pollbody+'\n'+(port/'tests/portable_cases.c').read_text()
   (t/'queue.c').write_text(c)
   suites.append(('queue',['Y771Event.c'],[]))
   hsi_trace=None
   for name,modules,flags in suites:
    if name not in args.suites:continue
    input_c=t/'queue.c' if name=='queue' else port/'tests'/(name+'_cases.c')
    if name=='runtime':
     callback_names=['OnPrepareHardware','OnReleaseHardware','OnD0Entry','OnD0Exit']
     callback_bodies={n:helpers.function(source,n) for n in callback_names}
     assert callback_bodies=={n:helpers.function((exp1/'Device.c').read_text(),n) for n in callback_names},'callback control changed outside runtime'
     out['actual_lifecycle_callbacks_sha256']={n:hashlib.sha256(v.encode()).hexdigest() for n,v in callback_bodies.items()}
     (t/'runtime_callbacks.inc').write_text('\n'.join(callback_bodies.values()))
     flags+=['-I',str(t)]
    exe=t/name
    cmd=['clang','-std=c11','-O1','-g','-fno-omit-frame-pointer','-fsanitize=address,undefined','-Wall','-Wextra','-Werror']+flags+['-I',str(port),str(input_c)]+[str(port/m) for m in modules]+['-o',str(exe)]
    tick=time.monotonic();b=subprocess.run(cmd,capture_output=True,text=True,timeout=60);ct=time.monotonic()-tick
    if b.returncode:raise AssertionError(name+' compile: '+b.stdout+b.stderr)
    tick=time.monotonic();r=subprocess.run([str(exe)],capture_output=True,text=True,timeout=60,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0:halt_on_error=1','UBSAN_OPTIONS':'halt_on_error=1'});rt=time.monotonic()-tick
    if r.returncode:raise AssertionError(name+' run: '+r.stdout+r.stderr)
    if name=='hsi':hsi_trace=r.stderr;hsi_stdout=r.stdout
    if name=='runtime':
     sizes=list(map(int,r.stderr.strip().split()[1:]));assert len(sizes)==3
     out['runtime_diagnostic_sizes']=dict(zip(['hsi','state','lifecycle'],sizes))
    lines=r.stdout.splitlines();assert lines[-1]==f'PASS {len(lines)-1} groups',r.stdout
    out['suites'][name]={'compile_seconds':ct,'run_seconds':rt,'checks':lines[:-1],'stdout':r.stdout}
    out['checks'] += [name+':'+v for v in lines[:-1]]
  assert before==bindings() and baseline_before==baseline_bindings() and exp1_before==exp1_bindings(),'source changed during validation'
  out['passed']=True
 except Exception as e:out['error']=str(e)
 out['elapsed_seconds']=time.monotonic()-started;out['check_count']=len(out['checks'])
 args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps({k:out.get(k) for k in ('passed','check_count','elapsed_seconds','error')}))
 return 0 if out['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
