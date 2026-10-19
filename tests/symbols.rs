//! Authored binary-layout fixtures, not live PDB qualification evidence.
use dump_analyzer::report::{PdbIdentity, SymbolQuality};
use dump_analyzer::symbols::{
    parse_minidump_modules, qualify, read_minidump_modules, read_pdb_identity,
};

const GUID_BYTES: [u8; 16] = [
    0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn identity() -> PdbIdentity {
    PdbIdentity {
        guid: "00112233-4455-6677-8899-aabbccddeeff".into(),
        age: 2,
    }
}
fn dump() -> Vec<u8> {
    let mut b = vec![0; 256];
    b[..4].copy_from_slice(b"MDMP");
    put32(&mut b, 8, 1);
    put32(&mut b, 12, 32);
    put32(&mut b, 32, 4);
    put32(&mut b, 36, 112);
    put32(&mut b, 40, 44);
    put32(&mut b, 44, 1);
    b[48..56].copy_from_slice(&0x7ff600000000u64.to_le_bytes());
    put32(&mut b, 56, 0x10000);
    put32(&mut b, 64, 0x12345678);
    put32(&mut b, 68, 156);
    put32(&mut b, 124, 24);
    put32(&mut b, 128, 176);
    let name: Vec<u8> = "app.exe"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    put32(&mut b, 156, name.len() as u32);
    b[160..160 + name.len()].copy_from_slice(&name);
    b[176..180].copy_from_slice(b"RSDS");
    b[180..196].copy_from_slice(&GUID_BYTES);
    put32(&mut b, 196, 2);
    b
}
fn pdb() -> Vec<u8> {
    let mut b = vec![0; 512 * 4];
    b[..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
    put32(&mut b, 32, 512);
    put32(&mut b, 40, 4);
    put32(&mut b, 44, 16);
    put32(&mut b, 52, 1);
    put32(&mut b, 512, 2);
    put32(&mut b, 1024, 2);
    put32(&mut b, 1028, u32::MAX);
    put32(&mut b, 1032, 28);
    put32(&mut b, 1036, 3);
    put32(&mut b, 1536 + 8, 2);
    b[1536 + 12..1536 + 28].copy_from_slice(&GUID_BYTES);
    b
}
#[test]
fn independently_reads_rsds_and_info_stream_guid_age() {
    let modules = parse_minidump_modules(&dump()).unwrap();
    assert_eq!(modules[0].pdb, Some(identity()));
    assert_eq!(modules[0].name, "app.exe");
    let actual = read_pdb_identity(&pdb()).unwrap();
    assert_eq!(actual, identity());
    assert_eq!(
        qualify(
            modules[0].pdb.as_ref(),
            Some(&actual),
            SymbolQuality::Unverified
        ),
        SymbolQuality::Matched
    );
}
#[test]
fn wrong_guid_or_age_cannot_be_matched() {
    let wanted = identity();
    let mut actual = wanted.clone();
    actual.age += 1;
    assert_eq!(
        qualify(Some(&wanted), Some(&actual), SymbolQuality::Unverified),
        SymbolQuality::Mismatched
    );
    actual = wanted.clone();
    actual.guid = "ffffffff-ffff-ffff-ffff-ffffffffffff".into();
    assert_eq!(
        qualify(Some(&wanted), Some(&actual), SymbolQuality::Unverified),
        SymbolQuality::Mismatched
    );
    assert_eq!(
        qualify(Some(&wanted), None, SymbolQuality::Unverified),
        SymbolQuality::Unverified
    );
}
#[test]
fn corrupt_offsets_and_oversized_directories_fail_closed() {
    let mut d = dump();
    put32(&mut d, 12, u32::MAX);
    assert!(parse_minidump_modules(&d).is_err());
    let mut p = pdb();
    put32(&mut p, 44, u32::MAX);
    assert!(read_pdb_identity(&p).is_err());
    let mut p = pdb();
    put32(&mut p, 512, u32::MAX);
    assert!(read_pdb_identity(&p).is_err());
}
#[test]
fn file_inventory_reads_only_metadata_and_matches_slice_parser() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.dmp");
    std::fs::write(&path, dump()).unwrap();
    assert_eq!(
        read_minidump_modules(&path).unwrap(),
        parse_minidump_modules(&dump()).unwrap()
    );
}
