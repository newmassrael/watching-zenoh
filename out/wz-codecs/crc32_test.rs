

// SCE Forge: Auto-generated test-vector sidecar (RFC §synth-5-B B2)
// Companion to crc32.rs — do not edit; regenerate from the source SCXML.

#[test]
fn test_vector_crc32_l83() {
    let actual = crc32(&[0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8, 0x38u8, 0x39u8]);
    let expected: u32 = 0xfc4f2be9u32;
    assert_eq!(
        actual, expected,
        "<sce:test-vector> at SCXML L83: crc32(<313233343536373839>) returned {actual:?}, expected {expected:?}"
    );
}