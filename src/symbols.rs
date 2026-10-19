//! Independent minidump CodeView and PDB Info-stream identities.
//! A debugger's `(pdb symbols)` label is not an identity comparison.
use crate::report::{PdbIdentity, SymbolQuality};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpModule {
    pub name: String,
    pub base: u64,
    pub size: u32,
    pub timestamp: u32,
    pub pdb: Option<PdbIdentity>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}
fn guid(bytes: &[u8]) -> Option<String> {
    let b = bytes.get(..16)?;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{}-{}",
        u32_at(b, 0)?,
        u16::from_le_bytes(b[4..6].try_into().ok()?),
        u16::from_le_bytes(b[6..8].try_into().ok()?),
        hex::encode(&b[8..10]),
        hex::encode(&b[10..16])
    ))
}

/// Parse only the bounded module inventory and RSDS records; malformed offsets
/// fail closed. No module bytes, symbol names, or credentials are copied.
pub fn parse_minidump_modules(bytes: &[u8]) -> Result<Vec<DumpModule>, String> {
    if bytes.get(..4) != Some(b"MDMP") {
        return Err("not a minidump".into());
    }
    let count = u32_at(bytes, 8).ok_or("short header")? as usize;
    let directory = u32_at(bytes, 12).ok_or("short header")? as usize;
    if count > 4096 {
        return Err("stream count exceeds bound".into());
    }
    for i in 0..count {
        let at = directory
            .checked_add(i.checked_mul(12).ok_or("directory overflow")?)
            .ok_or("directory overflow")?;
        if u32_at(bytes, at).ok_or("short stream directory")? != 4 {
            continue;
        }
        let size = u32_at(bytes, at + 4).ok_or("short stream directory")? as usize;
        let rva = u32_at(bytes, at + 8).ok_or("short stream directory")? as usize;
        let stream = bytes
            .get(rva..rva.checked_add(size).ok_or("module stream overflow")?)
            .ok_or("module stream outside dump")?;
        let n = u32_at(stream, 0).ok_or("short module stream")? as usize;
        if n > 8192
            || n.checked_mul(108)
                .and_then(|v| v.checked_add(4))
                .is_none_or(|v| v > stream.len())
        {
            return Err("invalid module count/size".into());
        }
        let mut modules = Vec::with_capacity(n.min(crate::report::MAX_MODULES));
        // Keep a bounded inventory; the caller records omitted modules.
        for i in 0..n.min(8192) {
            let at = 4 + i * 108;
            let name_rva = u32_at(stream, at + 20).ok_or("short module")? as usize;
            let name_len = u32_at(bytes, name_rva).ok_or("missing module name")? as usize;
            if name_len > 8192 || name_len % 2 != 0 {
                return Err("invalid module name size".into());
            }
            let name_bytes = bytes
                .get(name_rva + 4..name_rva + 4 + name_len)
                .ok_or("module name outside dump")?;
            let name = String::from_utf16_lossy(
                &name_bytes
                    .chunks_exact(2)
                    .map(|p| u16::from_le_bytes([p[0], p[1]]))
                    .collect::<Vec<_>>(),
            );
            let cv_size = u32_at(stream, at + 76).ok_or("short module")? as usize;
            let cv_rva = u32_at(stream, at + 80).ok_or("short module")? as usize;
            let pdb = if cv_size >= 24 {
                bytes
                    .get(cv_rva..cv_rva.checked_add(cv_size).ok_or("CodeView overflow")?)
                    .filter(|cv| cv.get(..4) == Some(b"RSDS"))
                    .and_then(|cv| {
                        Some(PdbIdentity {
                            guid: guid(&cv[4..20])?,
                            age: u32_at(cv, 20)?,
                        })
                    })
            } else {
                None
            };
            modules.push(DumpModule {
                name,
                base: u64_at(stream, at).ok_or("short module")?,
                size: u32_at(stream, at + 8).ok_or("short module")?,
                timestamp: u32_at(stream, at + 16).ok_or("short module")?,
                pdb,
            });
        }
        return Ok(modules);
    }
    Err("minidump has no module-list stream".into())
}

/// Read the PDB's own MSF7 Info stream (stream 1), independently of its path.
/// The byte-slice API is for fixtures/local artifacts; production reads the
/// same small metadata remotely instead of downloading the PDB.
pub fn read_pdb_identity(bytes: &[u8]) -> Result<PdbIdentity, String> {
    if bytes.get(..32) != Some(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0") {
        return Err("unsupported PDB/MSF signature".into());
    }
    let page = u32_at(bytes, 32).ok_or("short MSF header")? as usize;
    let directory_len = u32_at(bytes, 44).ok_or("short MSF header")? as usize;
    let block_map = u32_at(bytes, 52).ok_or("short MSF header")? as usize;
    if !(512..=65536).contains(&page) || !page.is_power_of_two() || directory_len > 8 * 1024 * 1024
    {
        return Err("PDB directory exceeds bounds".into());
    }
    let blocks = directory_len.div_ceil(page);
    if blocks > page / 4 {
        return Err("unsupported PDB directory map".into());
    }
    let mut directory = Vec::with_capacity(directory_len);
    for i in 0..blocks {
        let index = u32_at(
            bytes,
            block_map
                .checked_mul(page)
                .and_then(|v| v.checked_add(i * 4))
                .ok_or("PDB offset overflow")?,
        )
        .ok_or("short PDB block map")? as usize;
        let at = index.checked_mul(page).ok_or("PDB page overflow")?;
        directory.extend_from_slice(
            bytes
                .get(at..at.checked_add(page).ok_or("PDB page overflow")?)
                .ok_or("PDB directory page outside file")?,
        );
    }
    directory.truncate(directory_len);
    let streams = u32_at(&directory, 0).ok_or("short PDB directory")? as usize;
    if !(2..=1_000_000).contains(&streams) {
        return Err("invalid PDB stream count".into());
    }
    let first_size = u32_at(&directory, 4).ok_or("short stream table")?;
    let info_size = u32_at(&directory, 8).ok_or("short stream table")?;
    if info_size < 28 || info_size == u32::MAX {
        return Err("PDB Info stream missing".into());
    }
    let first_pages = if first_size == u32::MAX {
        0
    } else {
        (first_size as usize).div_ceil(page)
    };
    let index_at = 4usize
        .checked_add(streams.checked_mul(4).ok_or("PDB offset overflow")?)
        .and_then(|v| v.checked_add(first_pages * 4))
        .ok_or("PDB offset overflow")?;
    let info_page = u32_at(&directory, index_at).ok_or("short PDB stream map")? as usize;
    let at = info_page.checked_mul(page).ok_or("PDB page overflow")?;
    let info = bytes
        .get(at..at.checked_add(28).ok_or("PDB page overflow")?)
        .ok_or("PDB Info outside file")?;
    Ok(PdbIdentity {
        guid: guid(&info[12..28]).ok_or("short GUID")?,
        age: u32_at(info, 8).ok_or("short age")?,
    })
}

pub fn qualify(
    expected: Option<&PdbIdentity>,
    loaded: Option<&PdbIdentity>,
    fallback: SymbolQuality,
) -> SymbolQuality {
    match (expected, loaded) {
        (Some(a), Some(b)) if a == b => SymbolQuality::Matched,
        (Some(_), Some(_)) => SymbolQuality::Mismatched,
        _ => fallback,
    }
}

/// Seek-only inventory acquisition: large/full dumps are never loaded into RAM.
pub fn read_minidump_modules(path: &std::path::Path) -> Result<Vec<DumpModule>, String> {
    use std::io::{Read, Seek, SeekFrom};
    fn read_at(file: &mut std::fs::File, offset: u64, size: usize) -> Result<Vec<u8>, String> {
        let mut bytes = vec![0; size];
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(&mut bytes))
            .map_err(|e| format!("reading minidump metadata: {e}"))?;
        Ok(bytes)
    }
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("opening minidump metadata: {e}"))?;
    let header = read_at(&mut file, 0, 32)?;
    if header.get(..4) != Some(b"MDMP") {
        return Err("not a minidump".into());
    }
    let count = u32_at(&header, 8).ok_or("short header")? as usize;
    if count > 4096 {
        return Err("stream count exceeds bound".into());
    }
    let directory = read_at(
        &mut file,
        u32_at(&header, 12).ok_or("short header")? as u64,
        count * 12,
    )?;
    for entry in directory.chunks_exact(12) {
        if u32_at(entry, 0) != Some(4) {
            continue;
        }
        let size = u32_at(entry, 4).ok_or("short directory")? as usize;
        if size > 4 + 8192 * 108 {
            return Err("module stream exceeds bound".into());
        }
        let stream = read_at(
            &mut file,
            u32_at(entry, 8).ok_or("short directory")? as u64,
            size,
        )?;
        let count = u32_at(&stream, 0).ok_or("short module stream")? as usize;
        if count > 8192
            || count
                .checked_mul(108)
                .and_then(|n| n.checked_add(4))
                .is_none_or(|n| n > stream.len())
        {
            return Err("invalid module count/size".into());
        }
        let mut result = Vec::with_capacity(count);
        for entry in stream[4..].chunks_exact(108).take(count) {
            let name_rva = u32_at(entry, 20).ok_or("short module")? as u64;
            let name_size = read_at(&mut file, name_rva, 4)?;
            let name_size = u32_at(&name_size, 0).ok_or("short name")? as usize;
            if name_size > 8192 || name_size % 2 != 0 {
                return Err("invalid module name size".into());
            }
            let name = read_at(&mut file, name_rva + 4, name_size)?;
            let name = String::from_utf16_lossy(
                &name
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect::<Vec<_>>(),
            );
            let cv_size = u32_at(entry, 76).ok_or("short module")? as usize;
            let pdb = if cv_size >= 24 {
                let cv = read_at(
                    &mut file,
                    u32_at(entry, 80).ok_or("short module")? as u64,
                    24,
                )?;
                if cv.get(..4) == Some(b"RSDS") {
                    Some(PdbIdentity {
                        guid: guid(&cv[4..20]).ok_or("short GUID")?,
                        age: u32_at(&cv, 20).ok_or("short age")?,
                    })
                } else {
                    None
                }
            } else {
                None
            };
            result.push(DumpModule {
                name,
                base: u64_at(entry, 0).ok_or("short module")?,
                size: u32_at(entry, 8).ok_or("short module")?,
                timestamp: u32_at(entry, 16).ok_or("short module")?,
                pdb,
            });
        }
        return Ok(result);
    }
    Err("minidump has no module-list stream".into())
}
