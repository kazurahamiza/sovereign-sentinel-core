#include <ntddk.h>

PVOID g_ElamCallbackHandle = NULL;

// OS Boot-Driver Evaluation Callback Routine
VOID NTAPI ElamBootDriverCallback(
    _In_ PVOID ClassifyContext,
    _In_ BDCB_CALLBACK_TYPE CallbackType,
    _In_ PBDCB_IMAGE_INFORMATION ImageInformation
) {
    UNREFERENCED_PARAMETER(ClassifyContext);

    // Only process driver initialization events
    if (CallbackType == BdcbStatusUpdate) {
        if (ImageInformation->Classification == BdcbClassificationKnownBad) {
            
            // Block execution of the malicious boot driver
            ImageInformation->ImageFlags |= BDCB_IMAGE_FLAG_BLOCK;
            
            DbgPrint("[!] ELAM Guard: Blocked Malicious Boot Driver: %wZ\n", 
                     &ImageInformation->ImageName);
        }
    }
}

NTSTATUS InitializeElamGuard(_In_ PDRIVER_OBJECT DriverObject) {
    NTSTATUS status;

    // Register callback to inspect all subsequent boot-start drivers
    status = IoRegisterBootDriverCallback(
        ElamBootDriverCallback,
        NULL,
        &g_ElamCallbackHandle
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] ELAM Guard: Failed to register boot driver callback (0x%08X)\n", status);
    }

    return status;
}
