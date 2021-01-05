#define INITGUID
#define FLOW_CONTEXT_POOL_TAG 'tag'

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>


DEFINE_GUID(WFP_STABLE, 0x479f1f05, 0xfe29, 0x40, 0x73, 0xa1, 0x48, 0x28, 0x37, 0xd3, 0x0e, 0xdb, 0xcb);
DEFINE_GUID(WFP_SUB_LAYER, 0x479f1f05, 0xfe29, 0x40, 0x73, 0xa1, 0x48, 0x28, 0x37, 0xd3, 0x0e, 0xdb, 0xcd);

PDEVICE_OBJECT DeviceObject = NULL;
HANDLE Hengine = NULL;
UINT32 Reg_Callout_Id = 0, AddCalloutId;
UINT64 filterid = 0;
SIZE_T bytes;

HANDLE InjectionHandle = NULL;
UINT64 flowHandle = NULL;


VOID Unload(PDRIVER_OBJECT DriverObject)
{
	DbgPrintEx(0, 0, "Unloaded");
	IoDeleteDevice(DeviceObject);
	FwpsCalloutUnregisterById(Reg_Callout_Id);
}

VOID InjectionComplete(IN void* context,
	IN OUT NET_BUFFER_LIST* netBufferList,
	IN BOOLEAN dispatchLevel)
{
	DbgPrintEx(0,0,"InjectionCompleteFn");
	
	FWPS_TRANSPORT_SEND_PARAMS0* tlSendArgs = (FWPS_TRANSPORT_SEND_PARAMS0*)context;
	FwpsFreeCloneNetBufferList0(netBufferList, 0);
}


NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, GUID* filterkey, FWPS_FILTER* filter)
{
	return STATUS_SUCCESS;
}

VOID FlowCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext) {}

PVOID GetParams(PWSTR subkey)
{
	HANDLE Hreg;
	OBJECT_ATTRIBUTES attr;
	UNICODE_STRING keyname;
	//PVOID info; 
	NTSTATUS status;
	
	
	UNICODE_STRING ValueName;
	ULONG lenght = 0;
	PVOID Value;

	RtlInitUnicodeString(&keyname, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\WFP");

	InitializeObjectAttributes(&attr,&keyname,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);

	status = ZwOpenKey(&Hreg, KEY_READ, &attr);
	if (status != STATUS_SUCCESS) { DbgPrintEx(0, 0, "ZWOPENKEY ERROR"); return 0; }

	RtlInitUnicodeString(&ValueName, subkey);
	
	DbgPrintEx(0, 0, "VN - %wZ", ValueName);

	status = ZwQueryValueKey(Hreg, &ValueName, KeyValuePartialInformation, NULL, 0, &lenght);

	if (status != STATUS_SUCCESS)
	{
		KEY_VALUE_PARTIAL_INFORMATION* info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(PagedPool, lenght);
		if (info) 
		{ 
			status = ZwQueryValueKey(Hreg, &ValueName, KeyValuePartialInformation, info, lenght, &lenght);
			if (status == STATUS_SUCCESS)
			{
				Value = ExAllocatePool(PagedPool, lenght);
				RtlMoveMemory(Value, info->Data, info->DataLength);
				if (Value) 
				{ 
					return Value;
				}
				else { return 0; }
			}
			else { return 0; }
		}
		else { return 0; }
	}
	else { return 0; }
	return 0;
}

NTSTATUS FilterCallback(FWPS_INCOMING_VALUE* Values, FWPS_INCOMING_METADATA_VALUES0* MetaData,
	PVOID layerdata, const void* context, const FWPS_FILTER* filter, UINT64 flowcontext,
	FWPS_CLASSIFY_OUT* classifyout)
{
	FWPS_STREAM_CALLOUT_IO_PACKET0* packet;

	packet = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerdata;
	
	NET_BUFFER_LIST* netBufferList = packet->streamData->netBufferListChain;

	NTSTATUS status;
	//NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerdata;
	NET_BUFFER_LIST* clonedNetBufferList = NULL;
	FWPS_PACKET_INJECTION_STATE injectionState;
	FWPS_TRANSPORT_SEND_PARAMS0* tlSendArgs = NULL;
	ADDRESS_FAMILY af = AF_INET;

	if (FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_STREAM, &InjectionHandle) != STATUS_SUCCESS) { return 0; };

	status = FwpsAllocateCloneNetBufferList(netBufferList,NULL,NULL,0, &clonedNetBufferList);
	if (status != STATUS_SUCCESS)  { return 0; }; 

	classifyout->actionType = FWP_ACTION_BLOCK;
	classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	

	NET_BUFFER* netBuffer;
	PVOID data;
	char* modified;

	PWSTR findkey = L"Find";
	PWSTR replacekey = L"Replace";

	PVOID findstr = GetParams(findkey);
	if (!findstr) { DbgPrintEx(0, 0, "Needed Find param"); return 0; }
	PVOID replacestr = GetParams(replacekey);
	if (!replacestr) { DbgPrintEx(0, 0, "Needed Replace param"); return 0; }



	SIZE_T len = wcslen((wchar_t*)replacestr);
	

	void* buf = ExAllocatePool(PagedPool, len+1);
	RtlZeroMemory(buf, len+1);

	if (!buf) { DbgPrintEx(0, 0, "No buf"); return 0; }

	int loop = ((int)len * 2) - 2;

	for (int i = 0; i <= loop; i=i+2)
	{
		RtlCopyMemory((char*)buf+i/2, (char*)replacestr + i, 1);
	}
		

	for (netBuffer = NET_BUFFER_LIST_FIRST_NB(clonedNetBufferList);
		netBuffer != NULL;
		netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) 
	{
		data = NdisGetDataBuffer(netBuffer,32,NULL,1,0);
		
		if (data != NULL) 
		{ 
			modified = strstr((char*)data, (char*)findstr);
			DbgPrintEx(0, 0, "modified - %s", modified);
				if (modified)
			    { 
					memcpy((void*)modified, (char*)buf, len);
					
			    }
				else
				{
					DbgPrintEx(0, 0, "nb - %s", data);
				}
		}
	}

	classifyout->actionType = FWP_ACTION_PERMIT;
	classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	classifyout->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

	status = FwpsInjectTransportSendAsync0(InjectionHandle,NULL, MetaData->transportEndpointHandle,0,
		tlSendArgs,af, (COMPARTMENT_ID)MetaData->compartmentId,clonedNetBufferList, InjectionComplete , MetaData);

	if (status != STATUS_SUCCESS) { DbgPrintEx(0, 0, "last"); return 0; }

	

	clonedNetBufferList = NULL;
	tlSendArgs = NULL;

}

NTSTATUS WfpRegisterCallout(void)
{
	FWPS_CALLOUT Callout = { 0 };
	Callout.calloutKey = WFP_STABLE;
	Callout.flags = 0;
	Callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN3)FilterCallback;
	Callout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN3)NotifyCallback;
	Callout.flowDeleteFn = FlowCallback;

	return FwpsCalloutRegister(DeviceObject, &Callout, &Reg_Callout_Id);
}

NTSTATUS AddCallout(void)
{
	FWPM_CALLOUT callout = { 0 };
	callout.flags = 0;
	callout.displayData.name = L"ESTASCN";
	callout.displayData.description = L"Descr";
	callout.calloutKey = WFP_STABLE;
	callout.applicableLayer = FWPM_LAYER_STREAM_V4;
	return FwpmCalloutAdd(Hengine, &callout, NULL, &AddCalloutId);
}

NTSTATUS AddSublayer(void)
{
	FWPM_SUBLAYER sublayer = { 0 };

	sublayer.displayData.name = L"Flex";
	sublayer.displayData.description = L"Flex";
	sublayer.subLayerKey = WFP_SUB_LAYER;
	sublayer.weight = 65500;

	return FwpmSubLayerAdd(Hengine, &sublayer, NULL);
}

NTSTATUS AddFilter(void)
{

	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION condition[1] = { 0 };

	condition[0].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
	condition[0].matchType = FWP_MATCH_EQUAL;
	condition[0].conditionValue.type = FWP_UINT16;
	condition[0].conditionValue.uint16 = 80;

	filter.displayData.name = L"Flux";
	filter.displayData.description = L"Flux";
	filter.layerKey = FWPM_LAYER_STREAM_V4;
	filter.subLayerKey = WFP_SUB_LAYER;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 1;
	filter.filterCondition = condition;
	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = WFP_STABLE;
	NTSTATUS status = FwpmFilterAdd(Hengine, &filter, NULL, &filterid);

	return status;
}


NTSTATUS WfpOpenEngine(void)
{
	NTSTATUS status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &Hengine);
	return status;
}

NTSTATUS InitWFP(void)
{
	WfpOpenEngine();
	WfpRegisterCallout();
	AddCallout();
	AddSublayer();
	AddFilter();
	return STATUS_SUCCESS;
}

extern "C"  NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

	DriverObject->DriverUnload = Unload;

	status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	status = InitWFP();

	return status;
}