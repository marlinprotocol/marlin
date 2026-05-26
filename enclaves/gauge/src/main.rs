use goblin::pe::{PE, section_table::SectionTable};
use sha2::{Digest, Sha384};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;
use std::process;
use std::{env, fs};

const GPT_HEADER_SIZE: usize = 92;
const PCR11_SECTIONS: &[&str] = &[".linux", ".cmdline", ".initrd", ".uname", ".sbat"];
const FORBIDDEN_UKI_SECTIONS: &[&str] = &[".osrel"];

type DynError = Box<dyn std::error::Error>;

#[derive(Debug, PartialEq, Eq)]
struct ValidatedSection {
    name: &'static str,
    range: Range<usize>,
}

struct ValidatedUki {
    bytes: Vec<u8>,
    sections: Vec<ValidatedSection>,
}

impl ValidatedUki {
    fn parse(path: &str) -> Result<Self, DynError> {
        let bytes = fs::read(path)?;
        let sections = {
            let pe = PE::parse(&bytes)?;
            validate_uki_sections(bytes.len(), &pe.sections)?
        };

        Ok(Self { bytes, sections })
    }

    fn section_bytes(&self, name: &str) -> Result<&[u8], DynError> {
        let section = self
            .sections
            .iter()
            .find(|section| section.name == name)
            .ok_or_else(|| invalid_data(format!("validated UKI is missing {name}")))?;

        self.bytes.get(section.range.clone()).ok_or_else(|| {
            invalid_data(format!("validated range for {name} is out of bounds")).into()
        })
    }
}

fn main() -> Result<(), DynError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <disk_file> <uki_file> <output_file>", args[0]);
        process::exit(1);
    }

    let pcr5 = pcr5(&args[1])?;

    println!("\n--- PCR5 ---");
    println!("{}", hex::encode(pcr5));

    let pcr6 = pcr6()?;

    println!("\n--- PCR6 ---");
    println!("{}", hex::encode(pcr6));

    let uki = ValidatedUki::parse(&args[2])?;

    let pcr9 = pcr9(&uki)?;

    println!("\n--- PCR9 ---");
    println!("{}", hex::encode(pcr9));

    let pcr11 = pcr11(&uki)?;

    println!("\n--- PCR11 ---");
    println!("{}", hex::encode(pcr11));

    fs::write(
        &args[3],
        format!(
            r#"{{
  "Measurements": {{
    "HashAlgorithm": "SHA384",
    "PCR5": "{}",
    "PCR6": "{}",
    "PCR8": "{}",
    "PCR9": "{}",
    "PCR10": "{}",
    "PCR11": "{}",
    "PCR13": "{}",
    "PCR14": "{}",
    "PCR15": "{}"
  }}
}}
"#,
            hex::encode(pcr5),
            hex::encode(pcr6),
            "0".repeat(96),
            hex::encode(pcr9),
            "0".repeat(96),
            hex::encode(pcr11),
            "0".repeat(96),
            "0".repeat(96),
            "0".repeat(96),
        ),
    )?;

    Ok(())
}

fn pcr5(image_path: &str) -> Result<[u8; 48], DynError> {
    let mut file = File::open(image_path).expect("Failed to open file");

    // 1. Detect Sector Size (512 vs 4096)
    let sector_size = detect_sector_size(&mut file)?;
    println!("Detected Sector Size: {} bytes", sector_size);

    // 2. Read GPT Header
    // The header is always at LBA 1
    let header_offset = sector_size;
    file.seek(SeekFrom::Start(header_offset))?;

    let mut header_bytes = [0u8; GPT_HEADER_SIZE];
    file.read_exact(&mut header_bytes)?;

    // verify signature "EFI PART"
    if &header_bytes[0..8] != b"EFI PART" {
        eprintln!("Error: Valid GPT signature not found at LBA 1.");
        process::exit(1);
    }

    // Parse necessary fields from Header
    // Offset 72: PartitionEntryLBA (u64)
    // Offset 80: NumberOfPartitionEntries (u32)
    // Offset 84: SizeOfPartitionEntry (u32)
    let part_table_lba = u64::from_le_bytes(header_bytes[72..80].try_into()?);
    let num_entries = u32::from_le_bytes(header_bytes[80..84].try_into()?);
    let entry_size = u32::from_le_bytes(header_bytes[84..88].try_into()?);

    println!(
        "GPT Info: Table at LBA {}, {} entries of {} bytes.",
        part_table_lba, num_entries, entry_size
    );

    // 3. Read Partition Table
    let table_offset = part_table_lba * sector_size;
    file.seek(SeekFrom::Start(table_offset))?;

    let mut active_partitions: Vec<Vec<u8>> = Vec::new();

    for _ in 0..num_entries {
        let mut entry_buf = vec![0u8; entry_size as usize];
        file.read_exact(&mut entry_buf)?;

        // The first 16 bytes are the Partition Type GUID.
        // If all zeros, the partition is empty.
        let type_guid = &entry_buf[0..16];
        if type_guid.iter().any(|&b| b != 0) {
            active_partitions.push(entry_buf);
        }
    }

    println!("Found {} active partitions.", active_partitions.len());

    // 4. Construct Event Payload
    // Format: [GPT Header (92b)] + [Count (8b)] + [Active Partition Entries]

    let mut event_payload = Vec::new();

    // A. Add Header
    event_payload.extend_from_slice(&header_bytes);

    // B. Add Count (The firmware uses the ACTIVE count, not total count)
    // Must be 64-bit Little Endian
    let count_val = active_partitions.len() as u64;
    event_payload.extend_from_slice(&count_val.to_le_bytes());

    // C. Add Active Entries
    for part in active_partitions {
        event_payload.extend_from_slice(&part);
    }

    // calculate pcr5
    let pcr5 = extend_pcr([0; 48], &[&[0; 4]]);
    let pcr5 = extend_pcr(pcr5, &[&event_payload]);
    let pcr5 = extend_pcr(pcr5, &[b"Exit Boot Services Invocation"]);
    let pcr5 = extend_pcr(pcr5, &[b"Exit Boot Services Returned with Success"]);

    Ok(pcr5)
}

fn pcr6() -> Result<[u8; 48], DynError> {
    let pcr6 = extend_pcr([0; 48], &[[0; 4].as_ref()]);

    Ok(pcr6)
}

fn pcr9(uki: &ValidatedUki) -> Result<[u8; 48], DynError> {
    let cmdline_bytes = uki.section_bytes(".cmdline")?;
    if cmdline_bytes.contains(&0) {
        return Err(invalid_data(".cmdline section contains an embedded NUL byte").into());
    }
    let cmdline = std::str::from_utf8(cmdline_bytes)?;
    let cmdline_utf16 = cmdline
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();

    let pcr9 = extend_pcr([0; 48], &[cmdline_utf16.as_ref()]);
    let pcr9 = extend_pcr(pcr9, &[uki.section_bytes(".initrd")?]);

    Ok(pcr9)
}

fn pcr11(uki: &ValidatedUki) -> Result<[u8; 48], DynError> {
    // Section ordering, filtered to what is expected to be present and measured.
    // ref: https://github.com/systemd/systemd/blob/v258/src/fundamental/uki.h#L8
    let mut pcr11 = [0; 48];
    for item in PCR11_SECTIONS {
        let temp = extend_pcr(pcr11, &[item.as_bytes(), &[0]]);
        pcr11 = extend_pcr(temp, &[uki.section_bytes(item)?]);
    }

    Ok(pcr11)
}

fn validate_uki_sections(
    bytes_len: usize,
    sections: &[SectionTable],
) -> Result<Vec<ValidatedSection>, DynError> {
    for section in sections {
        let name = section_name(section)?;
        if FORBIDDEN_UKI_SECTIONS.contains(&name) {
            return Err(invalid_data(format!(
                "{name} section must be stripped before measurement"
            ))
            .into());
        }
    }

    let mut validated = Vec::with_capacity(PCR11_SECTIONS.len());
    for required in PCR11_SECTIONS {
        let mut found = None;
        for section in sections {
            if section_name(section)? == *required {
                if found.is_some() {
                    return Err(invalid_data(format!("duplicate {required} section")).into());
                }
                found = Some(section);
            }
        }

        let section =
            found.ok_or_else(|| invalid_data(format!("missing required {required} section")))?;
        let range = measured_section_range(required, section, bytes_len)?;
        validated.push(ValidatedSection {
            name: required,
            range,
        });
    }

    Ok(validated)
}

fn measured_section_range(
    name: &str,
    section: &SectionTable,
    bytes_len: usize,
) -> Result<Range<usize>, DynError> {
    checked_section_range(
        name,
        usize::try_from(section.pointer_to_raw_data)?,
        usize::try_from(section.virtual_size)?,
        usize::try_from(section.size_of_raw_data)?,
        bytes_len,
    )
}

fn checked_section_range(
    name: &str,
    start: usize,
    virtual_size: usize,
    raw_size: usize,
    bytes_len: usize,
) -> Result<Range<usize>, DynError> {
    if virtual_size == 0 {
        return Err(invalid_data(format!("{name} section has an empty payload")).into());
    }
    if start == 0 {
        return Err(invalid_data(format!("{name} section has a zero raw-data pointer")).into());
    }
    if raw_size < virtual_size {
        return Err(invalid_data(format!(
            "{name} raw data is smaller than the measured virtual size"
        ))
        .into());
    }

    let end = start
        .checked_add(virtual_size)
        .ok_or_else(|| invalid_data(format!("{name} section range overflows")))?;
    if end > bytes_len {
        return Err(invalid_data(format!("{name} section range is outside the UKI file")).into());
    }

    Ok(start..end)
}

fn section_name(section: &SectionTable) -> Result<&str, DynError> {
    section
        .name()
        .map_err(|err| invalid_data(format!("invalid PE section name: {err}")).into())
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn extend_pcr(old: [u8; 48], new: &[&[u8]]) -> [u8; 48] {
    let new_hash = new
        .into_iter()
        .fold(Sha384::new(), |acc, new| acc.chain_update(new))
        .finalize();

    // println!(
    //     "old: {}\nnew: {}\nnew_hash: {}",
    //     hex::encode(old),
    //     hex::encode(&new[..new.len().min(256)]),
    //     hex::encode(new_hash)
    // );

    let mut hasher = Sha384::new();
    hasher.update(old);
    hasher.update(new_hash);
    hasher.finalize().into()
}

fn detect_sector_size(file: &mut File) -> Result<u64, std::io::Error> {
    let mut buf = [0u8; 8];

    // Check 512 offset
    file.seek(SeekFrom::Start(512))?;
    file.read_exact(&mut buf)?;
    if &buf == b"EFI PART" {
        return Ok(512);
    }

    // Check 4096 offset
    file.seek(SeekFrom::Start(4096))?;
    file.read_exact(&mut buf)?;
    if &buf == b"EFI PART" {
        return Ok(4096);
    }

    // Default failure
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Could not detect GPT header at offset 512 or 4096",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(name: &str, start: u32, virtual_size: u32, raw_size: u32) -> SectionTable {
        let mut section = SectionTable::default();
        section.name[..name.len()].copy_from_slice(name.as_bytes());
        section.pointer_to_raw_data = start;
        section.virtual_size = virtual_size;
        section.size_of_raw_data = raw_size;
        section
    }

    fn valid_sections() -> Vec<SectionTable> {
        vec![
            section(".linux", 100, 10, 16),
            section(".cmdline", 120, 12, 16),
            section(".initrd", 140, 20, 24),
            section(".uname", 180, 8, 8),
            section(".sbat", 200, 6, 8),
        ]
    }

    #[test]
    fn accepts_expected_repo_uki_sections() {
        let validated = validate_uki_sections(256, &valid_sections()).unwrap();

        assert_eq!(
            validated,
            vec![
                ValidatedSection {
                    name: ".linux",
                    range: 100..110
                },
                ValidatedSection {
                    name: ".cmdline",
                    range: 120..132
                },
                ValidatedSection {
                    name: ".initrd",
                    range: 140..160
                },
                ValidatedSection {
                    name: ".uname",
                    range: 180..188
                },
                ValidatedSection {
                    name: ".sbat",
                    range: 200..206
                },
            ]
        );
    }

    #[test]
    fn rejects_missing_required_section() {
        let sections = valid_sections()
            .into_iter()
            .filter(|section| section.name().unwrap() != ".initrd")
            .collect::<Vec<_>>();

        assert!(validate_uki_sections(256, &sections).is_err());
    }

    #[test]
    fn rejects_duplicate_required_section() {
        let mut sections = valid_sections();
        sections.push(section(".cmdline", 220, 4, 4));

        assert!(validate_uki_sections(256, &sections).is_err());
    }

    #[test]
    fn rejects_osrel_section() {
        let mut sections = valid_sections();
        sections.push(section(".osrel", 220, 4, 4));

        assert!(validate_uki_sections(256, &sections).is_err());
    }

    #[test]
    fn rejects_out_of_bounds_section_range() {
        let mut sections = valid_sections();
        sections[2] = section(".initrd", 250, 20, 20);

        assert!(validate_uki_sections(256, &sections).is_err());
    }

    #[test]
    fn rejects_overflowing_section_range() {
        assert!(checked_section_range(".linux", usize::MAX, 1, 1, usize::MAX).is_err());
    }

    #[test]
    fn rejects_raw_data_smaller_than_virtual_size() {
        let mut sections = valid_sections();
        sections[2] = section(".initrd", 140, 20, 19);

        assert!(validate_uki_sections(256, &sections).is_err());
    }

    #[test]
    fn rejects_zero_length_required_section() {
        let mut sections = valid_sections();
        sections[2] = section(".initrd", 140, 0, 0);

        assert!(validate_uki_sections(256, &sections).is_err());
    }

    #[test]
    fn rejects_cmdline_with_embedded_nul() {
        let sections = validate_uki_sections(256, &valid_sections()).unwrap();
        let mut bytes = vec![0; 256];
        bytes[120..132].copy_from_slice(b"one\0two  arg");
        bytes[140..160].copy_from_slice(&[7; 20]);
        let uki = ValidatedUki { bytes, sections };

        assert!(pcr9(&uki).is_err());
    }

    #[test]
    fn pcr9_uses_validated_cmdline_and_initrd_ranges() {
        let sections = validate_uki_sections(256, &valid_sections()).unwrap();
        let mut bytes = vec![0; 256];
        bytes[120..132].copy_from_slice(b"console=test");
        bytes[140..160].copy_from_slice(&[7; 20]);
        let uki = ValidatedUki { bytes, sections };

        let cmdline_utf16 = "console=test"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let expected = extend_pcr(extend_pcr([0; 48], &[cmdline_utf16.as_ref()]), &[&[7; 20]]);

        assert_eq!(pcr9(&uki).unwrap(), expected);
    }

    #[test]
    fn pcr11_uses_validated_sections_in_fixed_order() {
        let sections = validate_uki_sections(256, &valid_sections()).unwrap();
        let mut bytes = vec![0; 256];
        bytes[100..110].copy_from_slice(&[1; 10]);
        bytes[120..132].copy_from_slice(&[2; 12]);
        bytes[140..160].copy_from_slice(&[3; 20]);
        bytes[180..188].copy_from_slice(&[4; 8]);
        bytes[200..206].copy_from_slice(&[5; 6]);
        let uki = ValidatedUki { bytes, sections };

        let mut expected = [0; 48];
        for name in PCR11_SECTIONS {
            expected = extend_pcr(
                extend_pcr(expected, &[name.as_bytes(), &[0]]),
                &[uki.section_bytes(name).unwrap()],
            );
        }

        assert_eq!(pcr11(&uki).unwrap(), expected);
    }
}
