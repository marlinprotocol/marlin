use goblin::pe::PE;
use sha2::{Digest, Sha384};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::process;
use std::{env, fs};

const GPT_HEADER_SIZE: usize = 92;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let pcr11 = pcr11(&args[2])?;

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
            "0".repeat(96),
            hex::encode(pcr11),
            "0".repeat(96),
            "0".repeat(96),
            "0".repeat(96),
        ),
    )?;

    Ok(())
}

fn pcr5(image_path: &str) -> Result<[u8; 48], Box<dyn std::error::Error>> {
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

    // 5. Output Results
    let hex_string = hex::encode(&event_payload);
    println!("\n--- Generated Event Data (Hex) ---");
    println!("{}", hex_string);

    // calculate pcr5
    let pcr5 = extend_pcr([0; 48], &[0; 4]);
    let pcr5 = extend_pcr(pcr5, &event_payload);
    let pcr5 = extend_pcr(pcr5, b"Exit Boot Services Invocation");
    let pcr5 = extend_pcr(pcr5, b"Exit Boot Services Returned with Success");

    Ok(pcr5)
}

fn pcr6() -> Result<[u8; 48], Box<dyn std::error::Error>> {
    let pcr6 = extend_pcr([0; 48], &[0; 4]);

    Ok(pcr6)
}

fn pcr11(uki: &str) -> Result<[u8; 48], Box<dyn std::error::Error>> {
    // section ordering, filtered to what is expected to be present and measured
    // ref: https://github.com/systemd/systemd/blob/v258/src/fundamental/uki.h#L8
    static SECTIONS: &[&str] = &[".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"];

    let uki_bytes = fs::read(uki)?;
    let pe = PE::parse(&uki_bytes)?;

    let pcr11 = SECTIONS
        .iter()
        .try_fold([0; 48], |acc, &item| {
            let temp = extend_pcr(acc, &[item.as_bytes(), &[0]].concat());
            let section = pe
                .sections
                .iter()
                .find(|section| section.name().unwrap_or("") == item)?;
            let section_bytes = &uki_bytes[section.pointer_to_raw_data as usize
                ..section.pointer_to_raw_data as usize + section.virtual_size as usize];
            Some(extend_pcr(temp, &section_bytes))
        })
        .ok_or("failed to compute pcr11")?;

    Ok(pcr11)
}

fn extend_pcr(old: [u8; 48], new: &[u8]) -> [u8; 48] {
    let new_hash = Sha384::new_with_prefix(new).finalize();

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
