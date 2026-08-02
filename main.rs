// main.rs
use std::ffi::CString;
use std::os::windows::raw::HANDLE;
use windows_sys::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterSendMessage,
};

#[repr(C)]
struct ScanRequest {
    file_path: [u16; 260],
    process_id: u32,
}

#[repr(C)]
enum ScanVerdict {
    Allow = 0,
    Block = 1,
    Quarantine = 2,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[+] Starting Sovereign Sentinel User-Space Engine...");

    let port_name = wide_string("\\SovereignSentinelPort");
    let mut port_handle: HANDLE = std::ptr::null_mut();

    unsafe {
        let hr = FilterConnectCommunicationPort(
            port_name.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            &mut port_handle,
        );

        if hr != 0 {
            eprintln!("[-] Failed to connect to Kernel Bridge. Error: 0x{:X}", hr);
            return Ok(());
        }
    }

    println!("[+] Successfully connected to Kernel Bridge.");

    // Event Loop: Listen for kernel inspection requests
    loop {
        // 1. Receive file handle/path from driver
        // 2. Perform Heuristic Analysis (heuristics.rs)
        // 3. Send back verdict (Allow/Block/Quarantine)
    }
}

fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
