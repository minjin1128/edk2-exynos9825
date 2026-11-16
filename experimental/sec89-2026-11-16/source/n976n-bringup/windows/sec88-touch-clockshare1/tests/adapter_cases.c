/* Compile the complete production WDF adapter against field-level CM stubs. */
#include <stdio.h>
#include <stdlib.h>
#include "N976nWdfResources.h"
static unsigned groups;
#define CHECK(x) do { if(!(x)){fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);} }while(0)
#define GROUP(name) do {puts(name);++groups;}while(0)
static int zero_bytes(const void *p,size_t n){const unsigned char*b=p;for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;}
/* The actual WDK has both layouts; current ARM64 build omits Group. */
#if defined(NT_PROCESSOR_GROUPS)
#define EXPECT_GROUP(n) (n)
static void set_group(CM_PARTIAL_RESOURCE_DESCRIPTOR *d,unsigned group){d->u.Interrupt.Group=(uint16_t)group;}
#else
#define EXPECT_GROUP(n) 0U
static void set_group(CM_PARTIAL_RESOURCE_DESCRIPTOR *d,unsigned group){(void)d;(void)group;}
#endif
static CM_PARTIAL_RESOURCE_DESCRIPTOR connection(void){
    CM_PARTIAL_RESOURCE_DESCRIPTOR d={0};d.Type=CmResourceTypeConnection;d.ShareDisposition=CmResourceShareDeviceExclusive;
    d.u.Connection.Class=CM_RESOURCE_CONNECTION_CLASS_SERIAL;d.u.Connection.Type=CM_RESOURCE_CONNECTION_TYPE_SERIAL_I2C;
    d.u.Connection.IdLowPart=0x89ABCDEF;d.u.Connection.IdHighPart=0x12345678;return d;
}
static CM_PARTIAL_RESOURCE_DESCRIPTOR interrupt(unsigned vector,unsigned trigger){
    CM_PARTIAL_RESOURCE_DESCRIPTOR d={0};d.Type=CmResourceTypeInterrupt;d.ShareDisposition=CmResourceShareDeviceExclusive;
    d.Flags=(uint16_t)trigger;d.u.Interrupt.Vector=vector;d.u.Interrupt.Level=5;d.u.Interrupt.Affinity=1;return d;
}
static CM_PARTIAL_RESOURCE_DESCRIPTOR memory(uint64_t base,uint32_t bytes){
    CM_PARTIAL_RESOURCE_DESCRIPTOR d={0};d.Type=CmResourceTypeMemory;d.ShareDisposition=CmResourceShareDeviceExclusive;
    d.u.Memory.Start.QuadPart=(int64_t)base;d.u.Memory.Length=bytes;return d;
}
static void bind(MOCK_CM_LIST*l,CM_PARTIAL_RESOURCE_DESCRIPTOR*d,unsigned n){
    memset(l,0,sizeof(*l));l->Count=n;for(unsigned i=0;i<n;i++)l->Descriptors[i]=&d[i];
}
static void fixture(CM_PARTIAL_RESOURCE_DESCRIPTOR r[5],CM_PARTIAL_RESOURCE_DESCRIPTOR t[5],MOCK_CM_LIST*rl,MOCK_CM_LIST*tl,unsigned controller){
    memset(r,0,sizeof(*r)*5);if(controller){
        r[0]=memory(0x104B0000,0x1000);r[1]=memory(0x10400000,0x8000);
        r[2]=memory(0x10421000,0x1000);r[3]=memory(0x10430000,0x1000);
        r[4]=interrupt(420,CM_RESOURCE_INTERRUPT_LATCHED);
    }else{r[0]=connection();r[1]=interrupt(8,CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE);}
    unsigned count=controller?5:2;memcpy(t,r,sizeof(*r)*5);t[count-1].u.Interrupt.Vector=0x3456;
    t[count-1].u.Interrupt.Level=7;set_group(&t[count-1],4);t[count-1].u.Interrupt.Affinity=UINT64_C(1)<<32;
    bind(rl,r,count);bind(tl,t,count);
}
static void normalized_bad(const CM_PARTIAL_RESOURCE_DESCRIPTOR *d){
    struct{uint64_t pre;N976N_RESOURCE out;uint64_t post;} c;
    memset(&c,0xA5,sizeof(c));c.pre=UINT64_C(0x0123456789ABCDEF);c.post=~c.pre;
    CHECK(N976nNormalizeCmResource(d,&c.out)!=N976nResourceOk);CHECK(zero_bytes(&c.out,sizeof(c.out)));
    CHECK(c.pre==UINT64_C(0x0123456789ABCDEF)&&c.post==~c.pre);
}
static void capture_bad(MOCK_CM_LIST *raw,MOCK_CM_LIST *translated,unsigned controller){
    union{N976N_TOUCH_RESOURCE_PLAN touch;N976N_CONTROLLER_RESOURCE_PLAN ctl;} plan;
    memset(&plan,0xA5,sizeof(plan));
    if(controller){CHECK(N976nCaptureControllerResources(raw,translated,&plan.ctl)!=N976nResourceOk);CHECK(zero_bytes(&plan.ctl,sizeof(plan.ctl)));}
    else{CHECK(N976nCaptureTouchResources(raw,translated,&plan.touch)!=N976nResourceOk);CHECK(zero_bytes(&plan.touch,sizeof(plan.touch)));}
}
int main(void){
    CM_PARTIAL_RESOURCE_DESCRIPTOR d,r[5],t[5];N976N_RESOURCE normalized;MOCK_CM_LIST raw,translated;
    N976N_TOUCH_RESOURCE_PLAN touch;N976N_CONTROLLER_RESOURCE_PLAN ctl;
    GROUP("wdf_adapter_normalizes_actual_cm_field_types");
    d=connection();CHECK(N976nNormalizeCmResource(&d,&normalized)==N976nResourceOk);
    CHECK(normalized.Kind==N976nResourceConnection&&normalized.ConnectionId==UINT64_C(0x1234567889ABCDEF));
    CHECK(normalized.ConnectionClass==N976nConnectionSerial&&normalized.ConnectionType==N976nConnectionI2c&&normalized.Start==0&&normalized.Vector==0);
    d=interrupt(0x1234,CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE);d.u.Interrupt.Affinity=UINT64_C(1)<<60;set_group(&d,7);
    CHECK(N976nNormalizeCmResource(&d,&normalized)==N976nResourceOk);
    CHECK(normalized.Kind==N976nResourceInterrupt&&normalized.Vector==0x1234&&normalized.Level==5&&normalized.Affinity==(UINT64_C(1)<<60)&&normalized.Flags==N976nInterruptLevel&&normalized.Group==EXPECT_GROUP(7));
#if defined(NT_PROCESSOR_GROUPS)
    CHECK(sizeof(d.u.Interrupt.Level)==2);d.u.Interrupt.Level=0xFFFF;
    CHECK(N976nNormalizeCmResource(&d,&normalized)==N976nResourceOk);CHECK(normalized.Level==0xFFFF&&normalized.Group==7);
#else
    CHECK(sizeof(d.u.Interrupt.Level)==4);d.u.Interrupt.Level=0x10005;
    CHECK(N976nNormalizeCmResource(&d,&normalized)==N976nResourceOk);CHECK(normalized.Level==0x10005&&normalized.Group==0);
#endif
    d.Flags=CM_RESOURCE_INTERRUPT_LATCHED;CHECK(N976nNormalizeCmResource(&d,&normalized)==N976nResourceOk);CHECK(normalized.Flags==N976nInterruptEdge);
    d=memory(0x104B0000,0x1000);CHECK(N976nNormalizeCmResource(&d,&normalized)==N976nResourceOk);
    CHECK(normalized.Kind==N976nResourceMemory&&normalized.Start==0x104B0000&&normalized.Length==0x1000&&normalized.ConnectionId==0);
    GROUP("wdf_adapter_rejects_null_unknown_shared_and_extended_types");
    normalized_bad(NULL);d=connection();CHECK(N976nNormalizeCmResource(&d,NULL)==N976nResourceInvalid);
    for(unsigned bad=0;bad<5;bad++){d=connection();switch(bad){case 0:d.Type=0;break;case 1:d.Type=CmResourceTypeMemoryLarge;break;case 2:d.Type=255;break;case 3:d.ShareDisposition=CmResourceShareShared;break;case 4:d.ShareDisposition=0;break;}normalized_bad(&d);}
    GROUP("wdf_adapter_rejects_connection_modes_and_preserves_full_id");
    for(unsigned bad=0;bad<4;bad++){d=connection();switch(bad){case 0:d.Flags=1;break;case 1:d.u.Connection.Class=0;break;case 2:d.u.Connection.Type=2;break;case 3:d.u.Connection.Class=255;break;}normalized_bad(&d);}
    d=connection();d.u.Connection.IdHighPart=0xFFFFFFFF;d.u.Connection.IdLowPart=0xFFFFFFFF;
    CHECK(N976nNormalizeCmResource(&d,&normalized)==N976nResourceOk);CHECK(normalized.ConnectionId==UINT64_MAX);
    GROUP("wdf_adapter_rejects_msi_extra_flags_and_memory_modes");
    for(unsigned flag=2;flag<16;flag++){d=interrupt(420,flag);normalized_bad(&d);}
    d=interrupt(420,CM_RESOURCE_INTERRUPT_WAKE_HINT);normalized_bad(&d);
    d=interrupt(420,0x40);normalized_bad(&d);
    d=interrupt(8,CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT);CHECK(N976nNormalizeCmResource(&d,&normalized)==N976nResourceOk);CHECK(normalized.Flags==N976nInterruptLevel&&normalized.Secondary==1);
    d=interrupt(8,CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT|CM_RESOURCE_INTERRUPT_LATCHED);CHECK(N976nNormalizeCmResource(&d,&normalized)==N976nResourceOk);CHECK(normalized.Flags==N976nInterruptEdge&&normalized.Secondary==1);
    d=interrupt(8,CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT|CM_RESOURCE_INTERRUPT_MESSAGE);normalized_bad(&d);
    d=memory(0x104B0000,0x1000);d.Flags=CM_RESOURCE_MEMORY_READ_ONLY;normalized_bad(&d);
    d=memory(0x104B0000,0x1000);d.Flags=CM_RESOURCE_MEMORY_PREFETCHABLE;normalized_bad(&d);
    d=memory(0x104B0000,0);normalized_bad(&d);d=memory(UINT64_MAX,0x1000);normalized_bad(&d);
    GROUP("wdf_capture_touch_and_controller_valid_native_conversion_paths");
    fixture(r,t,&raw,&translated,0);CHECK(N976nCaptureTouchResources(&raw,&translated,&touch)==N976nResourceOk);
    CHECK(touch.ConnectionId==UINT64_C(0x1234567889ABCDEF)&&touch.RawInterruptVector==8&&touch.TranslatedInterruptVector==0x3456&&touch.TranslatedInterruptAffinity==(UINT64_C(1)<<32)&&touch.TranslatedInterruptGroup==EXPECT_GROUP(4));
    CHECK(raw.GetCalls==2&&translated.GetCalls==2);
    fixture(r,t,&raw,&translated,1);CHECK(N976nCaptureControllerResources(&raw,&translated,&ctl)==N976nResourceOk);
    CHECK(ctl.RawInterruptVector==420&&ctl.TranslatedInterruptVector==0x3456&&ctl.InterruptTrigger==N976nInterruptEdge&&ctl.Base[0]==0x104B0000&&ctl.Bytes[1]==0x8000&&ctl.TranslatedInterruptGroup==EXPECT_GROUP(4));
    CHECK(raw.GetCalls==5&&translated.GetCalls==5);
    GROUP("wdf_capture_missing_extra_and_mismatched_counts_before_descriptors");
    for(unsigned controller=0;controller<2;controller++)for(unsigned side=0;side<2;side++)for(unsigned count=0;count<8;count++){
        unsigned want=controller?5:2;if(count==want)continue;fixture(r,t,&raw,&translated,controller);
        (side?&translated:&raw)->Count=count;capture_bad(&raw,&translated,controller);
        CHECK(raw.GetCalls==0&&translated.GetCalls==0);
    }
    GROUP("wdf_capture_null_lists_outputs_and_truncated_descriptors");
    for(unsigned controller=0;controller<2;controller++){
        fixture(r,t,&raw,&translated,controller);capture_bad(NULL,&translated,controller);capture_bad(&raw,NULL,controller);
        if(controller)CHECK(N976nCaptureControllerResources(&raw,&translated,NULL)==N976nResourceInvalid);
        else CHECK(N976nCaptureTouchResources(&raw,&translated,NULL)==N976nResourceInvalid);
        CHECK(raw.GetCalls==0&&translated.GetCalls==0);
        for(unsigned side=0;side<2;side++)for(unsigned slot=0;slot<(controller?5U:2U);slot++){
            fixture(r,t,&raw,&translated,controller);(side?&translated:&raw)->Descriptors[slot]=NULL;
            capture_bad(&raw,&translated,controller);CHECK(raw.GetCalls<=slot+1&&translated.GetCalls<=slot+1);
        }
    }
    GROUP("wdf_capture_gpio_secondary_interrupt_and_opaque_processor_group");
    fixture(r,t,&raw,&translated,0);t[1].Flags=CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE|CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT;
    CHECK(N976nCaptureTouchResources(&raw,&translated,&touch)==N976nResourceOk);
    CHECK(touch.RawInterruptSecondary==0&&touch.TranslatedInterruptSecondary==1&&touch.TranslatedInterruptGroup==EXPECT_GROUP(4));
    r[1].Flags=t[1].Flags;CHECK(N976nCaptureTouchResources(&raw,&translated,&touch)==N976nResourceOk);
    CHECK(touch.RawInterruptSecondary==1&&touch.TranslatedInterruptSecondary==1);
    t[1].Flags=0;CHECK(N976nCaptureTouchResources(&raw,&translated,&touch)==N976nResourceOk);
    CHECK(touch.RawInterruptSecondary==1&&touch.TranslatedInterruptSecondary==0);
    fixture(r,t,&raw,&translated,1);t[4].Flags|=CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT;capture_bad(&raw,&translated,1);
    fixture(r,t,&raw,&translated,1);r[4].Flags|=CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT;capture_bad(&raw,&translated,1);
    GROUP("wdf_capture_late_failure_exposes_no_partial_resource_plan");
    for(unsigned controller=0;controller<2;controller++)for(unsigned side=0;side<2;side++){
        fixture(r,t,&raw,&translated,controller);(side?t:r)[controller?4:1].Flags=CM_RESOURCE_INTERRUPT_MESSAGE;
        capture_bad(&raw,&translated,controller);
        fixture(r,t,&raw,&translated,controller);(side?t:r)[controller?4:1].Type=CmResourceTypeMemoryLarge;
        capture_bad(&raw,&translated,controller);
    }
    GROUP("wdf_capture_semantic_pair_rejection_after_normalization");
    fixture(r,t,&raw,&translated,0);t[0].u.Connection.IdLowPart++;capture_bad(&raw,&translated,0);
    fixture(r,t,&raw,&translated,0);r[1].Flags=t[1].Flags=CM_RESOURCE_INTERRUPT_LATCHED;capture_bad(&raw,&translated,0);
    fixture(r,t,&raw,&translated,1);r[4].u.Interrupt.Vector=45;capture_bad(&raw,&translated,1);
    fixture(r,t,&raw,&translated,1);t[2].u.Memory.Start.QuadPart++;capture_bad(&raw,&translated,1);
    fixture(r,t,&raw,&translated,1);r[1]=r[0];t[1]=t[0];capture_bad(&raw,&translated,1);
    GROUP("production_prepare_metadata_success_and_failure_both_refuse_hardware");
    TEST_GATE_CONTEXT context;memset(&context,0xA5,sizeof(context));
    context.PeripheralId.QuadPart=0x1122334455667788;context.Interrupt=(void*)(uintptr_t)0x1234;context.SpbController=(void*)(uintptr_t)0x5678;
    fixture(r,t,&raw,&translated,0);t[1].Flags=CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT;
    CHECK(OnPrepareHardware(&context,&raw,&translated)==STATUS_NOT_SUPPORTED);
    CHECK(context.ResourceDiagnosticResult==N976nResourceOk&&context.ResourceDiagnostic.Valid==1&&context.ResourceDiagnostic.TranslatedInterruptSecondary==1);
    CHECK(context.PeripheralId.QuadPart==0x1122334455667788&&context.Interrupt==(void*)(uintptr_t)0x1234&&context.SpbController==(void*)(uintptr_t)0x5678);
    raw.Count=1;CHECK(OnPrepareHardware(&context,&raw,&translated)==STATUS_NOT_SUPPORTED);
    CHECK(context.ResourceDiagnosticResult==N976nResourceCount&&zero_bytes(&context.ResourceDiagnostic,sizeof(context.ResourceDiagnostic)));
    CHECK(context.PeripheralId.QuadPart==0x1122334455667788&&context.Interrupt==(void*)(uintptr_t)0x1234&&context.SpbController==(void*)(uintptr_t)0x5678);
    TEST_GATE_CONTEXT before=context;CHECK(OnD0Entry(&context,0)==STATUS_NOT_SUPPORTED);CHECK(memcmp(&before,&context,sizeof(context))==0);
    GROUP("production_release_retires_only_diagnostic_metadata");
    fixture(r,t,&raw,&translated,0);CHECK(OnPrepareHardware(&context,&raw,&translated)==STATUS_NOT_SUPPORTED);
    CHECK(context.ResourceDiagnostic.Valid==1);CHECK(OnReleaseHardware(&context,&translated)==STATUS_SUCCESS);
    CHECK(context.ResourceDiagnosticResult==N976nResourceInvalid&&zero_bytes(&context.ResourceDiagnostic,sizeof(context.ResourceDiagnostic)));
    CHECK(context.PeripheralId.QuadPart==0x1122334455667788&&context.Interrupt==(void*)(uintptr_t)0x1234&&context.SpbController==(void*)(uintptr_t)0x5678);
    printf("PASS %u groups\n",groups);return 0;
}
