use tss_esapi::attributes::SessionAttributes;
use tss_esapi::handles::PcrHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::PcrSelectionListBuilder;
use tss_esapi::Context;

pub struct HardwareAttestationCore {
    expected_pcr0_hash: Vec<u8>,
}

impl HardwareAttestationCore {
    pub fn new(expected_pcr0: Vec<u8>) -> Self {
        Self {
            expected_pcr0_hash: expected_pcr0,
        }
    }

    /// Queries the physical TPM 2.0 chip and reads current PCR 0 (BIOS/UEFI Hash)
    pub fn verify_firmware_integrity(&self) -> Result<bool, Box<dyn std::error::Error>> {
        // Establish connection with local TCG TPM 2.0 Context / Device Driver
        let mut context = Context::new(tss_esapi::TctiNameConf::from_environment_variable()?)?;

        // Construct PCR Selection List targeting PCR 0 with SHA-256
        let pcr_selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrHandle::Pcr0])
            .build()?;

        // Read PCR values directly from hardware
        let (_pcr_update_counter, _pcr_selection_out, pcr_values) =
            context.pcr_read(pcr_selection)?;

        if let Some(digest) = pcr_values.get(0) {
            let current_pcr0_bytes = digest.value();
            println!("[+] Hardware Sentinel: Physical TPM 2.0 Read Complete.");

            // Compare hardware PCR 0 digest against sealed baseline
            if current_pcr0_bytes == self.expected_pcr0_hash.as_slice() {
                println!("[+] Firmware Integrity Verified: PCR 0 matches trusted baseline.");
                return Ok(true);
            } else {
                println!("[!] ALERT: Hardware Tampering Detected! PCR 0 mismatch. SPI Flash / UEFI has been modified!");
                return Ok(false);
            }
        }

        Err("Failed to extract digest from physical TPM 2.0 chip.".into())
    }
}
