#include <ntddk.h>

// Protects Antivirus Process from Termination
OB_PREOP_CALLBACK_STATUS SelfDefenseProcessCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE TargetPid = PsGetProcessId(TargetProcess);

    // Replace g_ProtectedDaemonPid with the active PID of the Rust User-Space Daemon
    extern HANDLE g_ProtectedDaemonPid;

    if (TargetPid == g_ProtectedDaemonPid && g_ProtectedDaemonPid != NULL) {
        // Strip critical rights to kill or tamper with the user-space process
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ||
            OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
        }
    }

    return OB_PREOP_SUCCESS;
}

// Registry Self-Defense Callback
NTSTATUS RegistryProtectionCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
) {
    UNREFERENCED_PARAMETER(CallbackContext);
    
    REG_NOTIFY_CLASS OperationType = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    // Intercept Registry Key Deletion or Value Modification
    if (OperationType == RegNtPreDeleteKey || OperationType == RegNtPreSetValueKey) {
        // TODO: Validate if target path corresponds to Sentinel Service Key
        // Return STATUS_ACCESS_DENIED if unauthorized
    }

    return STATUS_SUCCESS;
}
