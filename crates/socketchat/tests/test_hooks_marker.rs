//! Tests build the socketchat program with socketchat-core's test-hooks
//! feature on (a dev-dependency turns it on), so its marker must be in that
//! program. Release builds leave the feature off, and
//! scripts/release-binary-check.sh fails one that holds the marker.

#[test]
fn test_hooks_marker_is_in_a_program_built_with_the_feature() {
    let marker = socketchat_core::TEST_HOOKS_MARKER.as_bytes();
    let program =
        std::fs::read(env!("CARGO_BIN_EXE_socketchat")).expect("read the socketchat program");
    assert!(
        program.windows(marker.len()).any(|w| w == marker),
        "the socketchat program built for tests does not hold the test-hooks marker"
    );
}

#[test]
fn release_check_looks_for_the_same_marker() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/release-binary-check.sh");
    let text = std::fs::read_to_string(&script).expect("read scripts/release-binary-check.sh");
    let line = format!("MARKER=\"{}\"", socketchat_core::TEST_HOOKS_MARKER);
    assert!(
        text.contains(&line),
        "{} does not look for {line}",
        script.display()
    );
}
