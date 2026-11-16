#ifndef SEC78_FAKE_STORPORT_H
#define SEC78_FAKE_STORPORT_H
#include "ntddk.h"
typedef struct {PHYSICAL_ADDRESS RangeStart;ULONG RangeLength;BOOLEAN RangeInMemory;} ACCESS_RANGE;
typedef struct {
 ULONG MaximumTransferLength,NumberOfPhysicalBreaks,AlignmentMask,NumberOfBuses;
 ULONG MaximumNumberOfTargets,MaximumNumberOfLogicalUnits,InitiatorBusId[1],CachesData,MapBuffers;
 ULONG Dma64BitAddresses,Dma32BitAddresses,SynchronizationModel,InterruptSynchronizationMode;
 ULONG MaxNumberOfIO,MaxIOsPerLun,InitialLunQueueDepth,NumberOfAccessRanges;
 ACCESS_RANGE (*AccessRanges)[4];
} PORT_CONFIGURATION_INFORMATION,*PPORT_CONFIGURATION_INFORMATION;
typedef struct _SCSI_REQUEST_BLOCK {unsigned short Length;UCHAR Function,SrbStatus,ScsiStatus,PathId,TargetId,Lun,QueueTag,QueueAction,CdbLength,SenseInfoBufferLength;
 ULONG SrbFlags,DataTransferLength,TimeOutValue;
 PVOID DataBuffer,SenseInfoBuffer,NextSrb,OriginalRequest,SrbExtension;ULONG_PTR InternalStatus;ULONG QueueSortKey,LinkTimeoutValue;UCHAR Cdb[16];
} SCSI_REQUEST_BLOCK,*PSCSI_REQUEST_BLOCK;
typedef enum {StorStartDevice=0,StorRemoveDevice=2,StorStopDevice=4,StorQueryCapabilities=9,StorQueryResourceRequirements=11,StorFilterResourceRequirements=13,StorSurpriseRemoval=23} STOR_PNP_ACTION;
typedef struct {unsigned short Length;UCHAR Function,SrbStatus,PnPSubFunction,PathId,TargetId,Lun;
 STOR_PNP_ACTION PnPAction;ULONG SrbFlags,DataTransferLength,TimeOutValue;
 PVOID DataBuffer,SenseInfoBuffer,NextSrb,OriginalRequest,SrbExtension;ULONG SrbPnPFlags,Reserved;UCHAR Reserved4[16];
} SCSI_PNP_REQUEST_BLOCK,*PSCSI_PNP_REQUEST_BLOCK;
#define SRB_FUNCTION_PNP 0x25
#define SRB_PNP_FLAGS_ADAPTER_REQUEST 1
typedef enum {ScsiQuerySupportedControlTypes,ScsiStopAdapter,ScsiRestartAdapter,ScsiOtherControl,ScsiAdapterSurpriseRemoval} SCSI_ADAPTER_CONTROL_TYPE;
typedef enum {ScsiAdapterControlSuccess,ScsiAdapterControlUnsuccessful} SCSI_ADAPTER_CONTROL_STATUS;
typedef struct {ULONG MaxControlType;BOOLEAN SupportedTypeList[5];} SCSI_SUPPORTED_CONTROL_TYPE_LIST,*PSCSI_SUPPORTED_CONTROL_TYPE_LIST;
typedef BOOLEAN (*PHW_PASSIVE_INITIALIZE_ROUTINE)(PVOID);
typedef struct {
 ULONG HwInitializationDataSize,AdapterInterfaceType,DeviceExtensionSize,SrbExtensionSize;
 ULONG (*HwFindAdapter)(PVOID,PVOID,PVOID,PCHAR,PPORT_CONFIGURATION_INFORMATION,PBOOLEAN);
 BOOLEAN (*HwBuildIo)(PVOID,PSCSI_REQUEST_BLOCK);
 BOOLEAN (*HwInitialize)(PVOID),(*HwStartIo)(PVOID,PSCSI_REQUEST_BLOCK),(*HwInterrupt)(PVOID),(*HwResetBus)(PVOID,ULONG);
 SCSI_ADAPTER_CONTROL_STATUS (*HwAdapterControl)(PVOID,SCSI_ADAPTER_CONTROL_TYPE,PVOID);
 ULONG NumberOfAccessRanges,MapBuffers,NeedPhysicalAddresses,TaggedQueuing,AutoRequestSense,MultipleRequestPerLu;
 ULONG FeatureSupport,SrbTypeFlags,AddressTypeFlags;
} HW_INITIALIZATION_DATA;
#define STOR_MAP_ALL_BUFFERS_INCLUDING_READ_WRITE 3
#define StorSynchronizeHalfDuplex 0
#define StorSynchronizeFullDuplex 1
#define InterruptSupportNone 0
#define SP_RETURN_FOUND 1
#define SP_RETURN_ERROR 3
#define Internal 0
#define InterfaceTypeUndefined ((ULONG)-1)
#define STOR_FEATURE_VIRTUAL_MINIPORT 0x00000001
#define STOR_FEATURE_SET_ADAPTER_INTERFACE_TYPE 0x00000800
#define STOR_FEATURE_ADAPTER_NOT_REQUIRE_IO_PORT 0x00000200
#define SRB_TYPE_FLAG_SCSI_REQUEST_BLOCK 1
#define ADDRESS_TYPE_FLAG_BTL8 1
#define SRB_FUNCTION_EXECUTE_SCSI 0
#define SRB_FUNCTION_IO_CONTROL 2
#define SRB_FUNCTION_SHUTDOWN 7
#define SRB_FUNCTION_FLUSH 8
#define SRB_STATUS_SUCCESS 1
#define SRB_STATUS_INVALID_REQUEST 6
#define SRB_STATUS_NO_DEVICE 8
#define SRB_STATUS_ERROR 4
#define SRB_STATUS_BUSY 5
#define SRB_STATUS_PENDING 0
#define SRB_STATUS_AUTOSENSE_VALID 0x80
#define SRB_FLAGS_DATA_IN 0x40
#define SRB_FLAGS_DATA_OUT 0x80
#define SRB_FLAGS_DISABLE_AUTOSENSE 0x20
ULONG StorPortQueryPerformanceCounter(PVOID,LARGE_INTEGER *,LARGE_INTEGER *);
void StorPortStallExecution(ULONG);
#define STOR_STATUS_SUCCESS 0
#define STOR_STATUS_BUSY 0xC100000CU
#define STOR_STATUS_INSUFFICIENT_RESOURCES 2
#define STOR_STATUS_INVALID_DEVICE_STATE 3
#define STOR_STATUS_INVALID_IRQL 4
#define STOR_STATUS_INVALID_PARAMETER 5
typedef VOID (*PHW_WORKITEM)(PVOID,PVOID,PVOID);
ULONG StorPortInitializeWorker(PVOID,PVOID *);
ULONG StorPortQueueWorkItem(PVOID,PHW_WORKITEM,PVOID,PVOID);
ULONG StorPortFreeWorker(PVOID,PVOID);
enum {RequestComplete,NextRequest};
BOOLEAN StorPortEnablePassiveInitialization(PVOID p,PHW_PASSIVE_INITIALIZE_ROUTINE callback);
void StorPortNotification(int kind,PVOID extension,PVOID request);
NTSTATUS StorPortInitialize(PVOID object,PVOID registry,HW_INITIALIZATION_DATA *init,PVOID hwcontext);
#endif
