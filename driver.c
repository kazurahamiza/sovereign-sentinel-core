// driver.c - Add Communication Port initialization
#include <fltKernel.h>

PFLT_PORT g_ServerPort = NULL;
PFLT_PORT g_ClientPort = NULL;

NTSTATUS ConnectNotifyCallback(
    IN PFLT_PORT ClientPort,
    IN PVOID ServerPortCookie,
    IN PVOID ConnectionContext,
    IN ULONG SizeOfContext,
    OUT PVOID *ConnectionCookie
) {
    g_ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID DisconnectNotifyCallback(IN PVOID ConnectionCookie) {
    FltCloseClientPort(g_FilterHandle, &g_ClientPort);
    g_ClientPort = NULL;
}

// In DriverEntry:
NTSTATUS SetupCommunicationPort(PFLT_FILTER Filter) {
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(L"\\SovereignSentinelPort");
    PSECURITY_DESCRIPTOR sd = NULL;

    // Create security descriptor for user-space access
    FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    NTSTATUS status = FltCreateCommunicationPort(
        Filter,
        &g_ServerPort,
        &oa,
        NULL,
        ConnectNotifyCallback,
        DisconnectNotifyCallback,
        NULL,
        1 // Max connections
    );

    FltFreeSecurityDescriptor(sd);
    return status;
}
