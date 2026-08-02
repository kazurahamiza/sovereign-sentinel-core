#include <ntddk.h>

// Status check for VBS / HVCI State via Hypervisor Enclave Interface
typedef struct _HVCI_STATE_INFORMATION {
    BOOLEAN VbsEnabled;
    BOOLEAN HvciEnabled;
    BOOLEAN StrictModeEnforced;
} HVCI_STATE_INFORMATION, *PHVCI_STATE_INFORMATION;

NTSTATUS QueryHypervisorMemoryIntegrity(_Out_ PHVCI_STATE_INFORMATION HvciInfo) {
    RtlZeroMemory(HvciInfo, sizeof(HVCI_STATE_INFORMATION));

    // 1. Validate if system is running under Hyper-V Isolation
    ULONG SystemSecureKernelFeatureInfo = 0;
    NTSTATUS status = ZwQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)0x9B, // SystemSecureKernelInformation
        &SystemSecureKernelFeatureInfo,
        sizeof(SystemSecureKernelFeatureInfo),
        NULL
    );

    if (NT_SUCCESS(status)) {
        // Bit 0: VBS Active, Bit 1: HVCI / Memory Integrity Enforced
        HvciInfo->VbsEnabled = (SystemSecureKernelFeatureInfo & 0x01) != 0;
        HvciInfo->HvciEnabled = (SystemSecureKernelFeatureInfo & 0x02) != 0;
        HvciInfo->StrictModeEnforced = (SystemSecureKernelFeatureInfo & 0x04) != 0;
    }

    if (!HvciInfo->HvciEnabled) {
        DbgPrint("[!] HVCI Guard Warning: VTL1 Memory Integrity is OFF. Operating System Kernel is vulnerable to W^X violations.\n");
    } else {
        DbgPrint("[+] HVCI Guard Active: Ring 0 Execution backed by VTL1 Hypervisor Page Enforcement.\n");
    }

    return status;
}
