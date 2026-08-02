#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// eBPF Map containing blocked SHA-256 hashes or Path IDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // Target PID or Path Hash
    __type(value, u8);  // Action Flag (1 = Block)
} blocked_targets SEC(".maps");

// LSM Hook: Intercepts execution before binary execution proceeds
SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Query eBPF Map for current process restriction
    u8 *blocked = bpf_map_lookup_elem(&blocked_targets, &pid);
    if (blocked && *blocked == 1) {
        bpf_printk("[!] eBPF Sentinel: Blocked unauthorized execution attempt by PID %d\n", pid);
        
        // Return Operation Not Permitted (-EPERM) to deny execution
        return -13; // -EPERM
    }

    return 0; // Allow execution
}
