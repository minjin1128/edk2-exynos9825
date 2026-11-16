/* SEC76 exact production metadata helpers; no hardware and no kernel execution. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "N976nResources.h"
static unsigned groups;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while (0)
#define GROUP(name) do { puts(name); ++groups; } while (0)
static int zero_bytes(const void *p, size_t n) {
    const unsigned char *b=p; for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;
}
static N976N_RESOURCE irq(unsigned vector, unsigned trigger) {
    N976N_RESOURCE d={0};d.Kind=N976nResourceInterrupt;d.Share=N976nShareExclusive;
    d.Vector=vector;d.Flags=trigger;d.Level=5;d.Affinity=1;return d;
}
static void touch_fixture(N976N_RESOURCE r[2],N976N_RESOURCE t[2]) {
    memset(r,0,sizeof(*r)*2);r[0].Kind=N976nResourceConnection;r[0].Share=N976nShareExclusive;
    r[0].ConnectionClass=N976nConnectionSerial;r[0].ConnectionType=N976nConnectionI2c;
    r[0].ConnectionId=UINT64_C(0x123456789ABCDEF0);r[1]=irq(8,N976nInterruptLevel);
    memcpy(t,r,sizeof(*r)*2);t[1].Vector=0x1234;t[1].Level=9;t[1].Group=3;t[1].Affinity=UINT64_C(1)<<40;
}
static void touch_bad(const N976N_RESOURCE *r,const N976N_RESOURCE *t,size_t n) {
    struct {uint64_t pre;N976N_TOUCH_RESOURCE_PLAN plan;uint64_t post;} out;
    memset(&out,0xA5,sizeof(out));out.pre=UINT64_C(0x123456789ABCDEF0);out.post=~out.pre;
    CHECK(N976nValidateTouchResources(r,t,n,&out.plan)!=N976nResourceOk);
    CHECK(zero_bytes(&out.plan,sizeof(out.plan)));
    CHECK(out.pre==UINT64_C(0x123456789ABCDEF0)&&out.post==~out.pre);
}
static void controller_bad(const N976N_RESOURCE *r,const N976N_RESOURCE *t,size_t n) {
    struct {uint64_t pre;N976N_CONTROLLER_RESOURCE_PLAN plan;uint64_t post;} out;
    memset(&out,0xA5,sizeof(out));out.pre=UINT64_C(0x123456789ABCDEF0);out.post=~out.pre;
    CHECK(N976nValidateControllerResources(r,t,n,&out.plan)!=N976nResourceOk);
    CHECK(zero_bytes(&out.plan,sizeof(out.plan)));
    CHECK(out.pre==UINT64_C(0x123456789ABCDEF0)&&out.post==~out.pre);
}
static void transfer_bad(unsigned command,unsigned n,unsigned address,unsigned speed) {
    struct {uint64_t pre;N976N_TRANSFER_PLAN plan;uint64_t post;} out;
    memset(&out,0xA5,sizeof(out));out.pre=UINT64_C(0x123456789ABCDEF0);out.post=~out.pre;
    CHECK(N976nPlanTouchRead((N976N_U8)command,n,address,speed,&out.plan)!=N976nResourceOk);
    CHECK(zero_bytes(&out.plan,sizeof(out.plan)));
    CHECK(out.pre==UINT64_C(0x123456789ABCDEF0)&&out.post==~out.pre);
}
/* Controller fixture is populated below from N976N source, not from library output. */
static const uint64_t controller_base[4]={0x104B0000,0x10400000,0x10421000,0x10430000};
static const uint64_t controller_bytes[4]={0x1000,0x8000,0x1000,0x1000};
static void controller_fixture(N976N_RESOURCE r[5],N976N_RESOURCE t[5]) {
    memset(r,0,sizeof(*r)*5);for(unsigned i=0;i<4;i++) {
        r[i].Kind=N976nResourceMemory;r[i].Share=N976nShareExclusive;
        r[i].Start=controller_base[i];r[i].Length=controller_bytes[i];
    }
    r[4]=irq(420,N976nInterruptLevel);memcpy(t,r,sizeof(*r)*5);
    t[4].Vector=0x2345;t[4].Level=11;t[4].Affinity=UINT64_C(1)<<35;
}
int main(void) {
    N976N_RESOURCE raw[5],translated[5];
    N976N_TOUCH_RESOURCE_PLAN tp;
    N976N_CONTROLLER_RESOURCE_PLAN cp;
    N976N_TRANSFER_PLAN sp;
    GROUP("resource_touch_valid_both_orders_and_opaque_interrupt_identity");
    for(unsigned order=0;order<2;order++) {
        touch_fixture(raw,translated);if(order){N976N_RESOURCE r=raw[0],t=translated[0];raw[0]=raw[1];raw[1]=r;translated[0]=translated[1];translated[1]=t;}
        CHECK(N976nValidateTouchResources(raw,translated,2,&tp)==N976nResourceOk);
        CHECK(tp.Valid==1&&tp.DescriptorCount==2&&tp.ConnectionId==UINT64_C(0x123456789ABCDEF0));
        CHECK(tp.RawInterruptVector==8&&tp.TranslatedInterruptVector==0x1234&&tp.TranslatedInterruptLevel==9&&tp.TranslatedInterruptGroup==3);
        CHECK(tp.TranslatedInterruptAffinity==(UINT64_C(1)<<40));
    }
    touch_fixture(raw,translated);raw[1].Vector=0xFFFFFFFFU;
    CHECK(N976nValidateTouchResources(raw,translated,2,&tp)==N976nResourceOk);
    CHECK(tp.RawInterruptVector==0xFFFFFFFFU&&tp.TranslatedInterruptVector==0x1234);
    GROUP("resource_touch_secondary_gpio_metadata_is_not_primary_gsiv");
    touch_fixture(raw,translated);translated[1].Secondary=1;
    CHECK(N976nValidateTouchResources(raw,translated,2,&tp)==N976nResourceOk);
    CHECK(tp.RawInterruptSecondary==0&&tp.TranslatedInterruptSecondary==1&&tp.TranslatedInterruptGroup==3);
    raw[1].Secondary=1;CHECK(N976nValidateTouchResources(raw,translated,2,&tp)==N976nResourceOk);
    translated[1].Secondary=0;CHECK(N976nValidateTouchResources(raw,translated,2,&tp)==N976nResourceOk);
    CHECK(tp.RawInterruptSecondary==1&&tp.TranslatedInterruptSecondary==0);
    raw[1].Secondary=2;touch_bad(raw,translated,2);
    touch_fixture(raw,translated);translated[1].Secondary=2;touch_bad(raw,translated,2);
    touch_fixture(raw,translated);translated[0].Group=1;touch_bad(raw,translated,2);
    touch_fixture(raw,translated);raw[0].Secondary=1;touch_bad(raw,translated,2);
    GROUP("resource_touch_null_count_and_output_canaries");
    touch_fixture(raw,translated);touch_bad(NULL,translated,2);touch_bad(raw,NULL,2);
    for(size_t n=0;n<8;n++)if(n!=2)touch_bad(raw,translated,n);
    touch_bad(raw,translated,SIZE_MAX);CHECK(N976nValidateTouchResources(raw,translated,2,NULL)==N976nResourceInvalid);
    GROUP("resource_touch_missing_duplicate_wrong_kind_and_no_mmio");
    for(unsigned bad=0;bad<7;bad++) {
        touch_fixture(raw,translated);
        switch(bad){case 0:raw[1]=raw[0];translated[1]=translated[0];break;
          case 1:raw[0]=raw[1];translated[0]=translated[1];break;
          case 2:raw[0].Kind=translated[0].Kind=N976nResourceUnknown;break;
          case 3:raw[0].Kind=translated[0].Kind=N976nResourceMemory;break;
          case 4:raw[0].Kind=99;translated[0].Kind=99;break;
          case 5:translated[1].Kind=N976nResourceMemory;break;
          case 6:raw[0].Start=translated[0].Start=0x104B0000;raw[0].Length=translated[0].Length=0x1000;break;
        }touch_bad(raw,translated,2);
    }
    GROUP("resource_touch_share_and_flags_fail_closed");
    for(unsigned slot=0;slot<2;slot++)for(unsigned side=0;side<2;side++) {
        touch_fixture(raw,translated);(side?translated:raw)[slot].Share=N976nShareUnknown;touch_bad(raw,translated,2);
        touch_fixture(raw,translated);(side?translated:raw)[slot].Flags=0x100;touch_bad(raw,translated,2);
    }
    touch_fixture(raw,translated);raw[1].Flags=translated[1].Flags=N976nInterruptEdge;touch_bad(raw,translated,2);
    touch_fixture(raw,translated);raw[0].Flags=translated[0].Flags=1;touch_bad(raw,translated,2);
    GROUP("resource_touch_connection_identity_fields_and_no_partial_plan");
    for(unsigned bad=0;bad<10;bad++) {
        touch_fixture(raw,translated);
        switch(bad){case 0:raw[0].ConnectionId=translated[0].ConnectionId=0;break;
          case 1:translated[0].ConnectionId++;break;
          case 2:raw[0].ConnectionClass=0;break;case 3:translated[0].ConnectionClass=2;break;
          case 4:raw[0].ConnectionType=0;break;case 5:translated[0].ConnectionType=2;break;
          case 6:raw[0].Vector=1;break;case 7:translated[0].Affinity=1;break;
          case 8:raw[0].Length=1;break;case 9:translated[0].Level=1;break;
        }touch_bad(raw,translated,2);
    }
    GROUP("resource_touch_translated_interrupt_and_extraneous_fields");
    for(unsigned bad=0;bad<11;bad++) {
        touch_fixture(raw,translated);
        switch(bad){case 0:translated[1].Vector=0;break;case 1:translated[1].Affinity=0;break;
          case 2:raw[1].Start=1;break;case 3:raw[1].Length=1;break;case 4:raw[1].ConnectionId=1;break;
          case 5:raw[1].ConnectionClass=1;break;case 6:raw[1].ConnectionType=1;break;
          case 7:translated[1].Start=1;break;case 8:translated[1].Length=1;break;
          case 9:translated[1].ConnectionClass=1;break;case 10:translated[1].ConnectionType=1;break;
        }touch_bad(raw,translated,2); /* Valid connection is encountered first: no partial output. */
    }
    GROUP("resource_controller_exact_regions_all_cyclic_orders");
    for(unsigned rotation=0;rotation<5;rotation++) {
        N976N_RESOURCE r[5],t[5];controller_fixture(r,t);
        for(unsigned i=0;i<5;i++){raw[i]=r[(i+rotation)%5];translated[i]=t[(i+rotation)%5];}
        CHECK(N976nValidateControllerResources(raw,translated,5,&cp)==N976nResourceOk);
        CHECK(cp.Valid==1&&cp.DescriptorCount==5&&cp.RawInterruptVector==420&&cp.TranslatedInterruptVector==0x2345);
        CHECK(cp.TranslatedInterruptLevel==11&&cp.TranslatedInterruptAffinity==(UINT64_C(1)<<35));
        for(unsigned i=0;i<4;i++)CHECK(cp.Base[i]==controller_base[i]&&cp.Bytes[i]==controller_bytes[i]);
    }
    GROUP("resource_controller_null_count_and_zero_output");
    controller_fixture(raw,translated);controller_bad(NULL,translated,5);controller_bad(raw,NULL,5);
    for(size_t n=0;n<8;n++)if(n!=5)controller_bad(raw,translated,n);
    controller_bad(raw,translated,SIZE_MAX);CHECK(N976nValidateControllerResources(raw,translated,5,NULL)==N976nResourceInvalid);
    GROUP("resource_controller_exact_mmio_bounds_and_translation");
    for(unsigned slot=0;slot<4;slot++)for(unsigned side=0;side<2;side++)for(unsigned field=0;field<6;field++) {
        controller_fixture(raw,translated);N976N_RESOURCE *d=&(side?translated:raw)[slot];
        switch(field){case 0:d->Start--;break;case 1:d->Start++;break;case 2:d->Length--;break;
          case 3:d->Length++;break;case 4:d->Length=0;break;case 5:d->Start=UINT64_MAX-1;d->Length=4;break;}
        controller_bad(raw,translated,5);
    }
    GROUP("resource_controller_duplicate_alias_missing_and_wrong_kind");
    for(unsigned slot=0;slot<4;slot++) {
        controller_fixture(raw,translated);raw[slot]=raw[(slot+1)%4];translated[slot]=translated[(slot+1)%4];controller_bad(raw,translated,5);
        controller_fixture(raw,translated);raw[slot].Start=translated[slot].Start=controller_base[0]+8;controller_bad(raw,translated,5);
        controller_fixture(raw,translated);raw[slot].Kind=translated[slot].Kind=N976nResourceConnection;controller_bad(raw,translated,5);
    }
    controller_fixture(raw,translated);raw[0]=raw[4];translated[0]=translated[4];controller_bad(raw,translated,5);
    controller_fixture(raw,translated);raw[4]=raw[0];translated[4]=translated[0];controller_bad(raw,translated,5);
    GROUP("resource_controller_memory_flags_share_and_extraneous_fields");
    for(unsigned side=0;side<2;side++)for(unsigned bad=0;bad<8;bad++) {
        controller_fixture(raw,translated);N976N_RESOURCE *d=&(side?translated:raw)[3];
        switch(bad){case 0:d->Share=N976nShareUnknown;break;case 1:d->Flags=1;break;
          case 2:d->ConnectionId=1;break;case 3:d->ConnectionClass=1;break;case 4:d->ConnectionType=1;break;
          case 5:d->Vector=1;break;case 6:d->Level=1;break;case 7:d->Affinity=1;break;}
        controller_bad(raw,translated,5);
    }
    GROUP("resource_controller_irq_identity_not_translated_vector_equality");
    controller_fixture(raw,translated);CHECK(N976nValidateControllerResources(raw,translated,5,&cp)==N976nResourceOk);
    raw[4].Vector=45;controller_bad(raw,translated,5);raw[4].Vector=388;controller_bad(raw,translated,5);
    raw[4].Vector=420;translated[4].Vector=45;CHECK(N976nValidateControllerResources(raw,translated,5,&cp)==N976nResourceOk);
    CHECK(cp.RawInterruptVector==420&&cp.TranslatedInterruptVector==45);
    GROUP("resource_controller_secondary_interrupt_rejected");
    for(unsigned side=0;side<2;side++){
        controller_fixture(raw,translated);(side?translated:raw)[4].Secondary=1;controller_bad(raw,translated,5);
        controller_fixture(raw,translated);(side?translated:raw)[0].Group=1;controller_bad(raw,translated,5);
        controller_fixture(raw,translated);(side?translated:raw)[0].Secondary=1;controller_bad(raw,translated,5);
    }
    GROUP("resource_controller_irq_trigger_preserved_not_hardware_proven");
    for(unsigned trigger=0;trigger<2;trigger++){
        controller_fixture(raw,translated);raw[4].Flags=translated[4].Flags=trigger;
        CHECK(N976nValidateControllerResources(raw,translated,5,&cp)==N976nResourceOk);CHECK(cp.InterruptTrigger==trigger);
    }
    for(unsigned bad=0;bad<6;bad++) {
        controller_fixture(raw,translated);
        switch(bad){case 0:raw[4].Flags=translated[4].Flags=2;break;case 1:raw[4].Flags=1;break;
          case 2:translated[4].Vector=0;break;case 3:translated[4].Affinity=0;break;
          case 4:raw[4].Share=0;break;case 5:translated[4].ConnectionId=1;break;}
        controller_bad(raw,translated,5);
    }
    GROUP("resource_transfer_valid_id_event_and_bounded_batch_stop_policy");
    for(unsigned command=0;command<3;command++)for(unsigned count=1;count<=31;count++) {
        unsigned code=command==0?0x52:command==1?0x60:0x61,n=command==0?3:command==1?16:count*16;
        CHECK(N976nPlanTouchRead((N976N_U8)code,n,0x48,400000,&sp)==N976nResourceOk);
        CHECK(sp.Valid==1&&sp.Address==0x48&&sp.SpeedHz==400000&&sp.MessageCount==2&&sp.Command==code);
        CHECK(sp.WriteBytes==1&&sp.ReadBytes==n&&sp.StopAfterWrite==1&&sp.StopAfterRead==1&&sp.RequiresSerializedBusOwnership==1);
    }
    GROUP("resource_transfer_all_commands_and_lengths_fail_closed");
    for(unsigned command=0;command<256;command++)for(unsigned n=0;n<=512;n++) {
        int valid=(command==0x52&&n==3)||(command==0x60&&n==16)||(command==0x61&&n!=0&&n<=496&&n%16==0);
        if(!valid)transfer_bad(command,n,0x48,400000);
    }
    transfer_bad(0x61,UINT32_MAX,0x48,400000);
    GROUP("resource_transfer_identity_null_and_canaries");
    transfer_bad(0x52,3,0x49,400000);transfer_bad(0x52,3,0x90,400000);transfer_bad(0x52,3,0,400000);
    transfer_bad(0x52,3,0x48,100000);transfer_bad(0x52,3,0x48,1000000);transfer_bad(0x52,3,0x48,0);
    CHECK(N976nPlanTouchRead(0x52,3,0x48,400000,NULL)==N976nResourceInvalid);
    printf("PASS %u groups\n",groups);return 0;
}
