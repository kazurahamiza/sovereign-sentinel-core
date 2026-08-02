#include <ntddk.h>
#include <fwpsk.h>

// Unique GUIDs for the WFP Callout
DEFINE_GUID(SENTINEL_ALE_CONNECT_CALLOUT_V4, 0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab);

// WFP Classify Callback: Intercepts Outbound Connection Requests
VOID NTAPI AleConnectClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
) {
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Extract Process ID requesting the network connection
    UINT64 processId = inMetaValues->processId;

    // Extract Remote IPv4 Address
    UINT32 remoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;

    // TODO: Cross-reference processId and remoteIp against local blocklists
    BOOLEAN is_malicious = FALSE; 

    if (is_malicious) {
        // Block the connection instantly at Ring 0
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        
        DbgPrint("[!] Network Sentinel: Blocked Outbound Connection from PID %I64u\n", processId);
    } else {
        // Allow legitimate traffic
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }
}
