#include <ntddk.h>

PVOID gRegistrationHandle = NULL;

OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Filter only process handle requests
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE TargetPid = PsGetProcessId(TargetProcess);

    // Target protection check: Example checking if target is LSASS or Engine Core
    if (TargetPid == (HANDLE)688) { // LSASS PID or protected process PID
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            // Strip write, read, and remote thread creation flags
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterMemoryGuard() {
    OB_CALLBACK_REGISTRATION ObCallbackReg;
    OB_OPERATION_REGISTRATION OperationReg;

    memset(&OperationReg, 0, sizeof(OperationReg));
    OperationReg.ObjectType = PsProcessType;
    OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationReg.PreOperation = PreOperationCallback;
    OperationReg.PostOperation = NULL;

    memset(&ObCallbackReg, 0, sizeof(ObCallbackReg));
    ObCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    ObCallbackReg.OperationRegistrationCount = 1;
    ObCallbackReg.RegistrationContext = NULL;
    ObCallbackReg.OperationRegistration = &OperationReg;

    return ObRegisterCallbacks(&ObCallbackReg, &gRegistrationHandle);
}

VOID UnregisterMemoryGuard() {
    if (gRegistrationHandle) {
        ObUnregisterCallbacks(gRegistrationHandle);
    }
}
