//! A profile closed in one thread opens again at once, even while another
//! thread starts programs. A program being started can hold a copy of every
//! open file for a moment, the profile's lock included.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use socketchat_core::client::Client;

const PASS: &str = "correct horse battery staple";

#[test]
fn a_closed_profile_opens_again_while_programs_start() {
    let stop = Arc::new(AtomicBool::new(false));
    let spawner = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = std::process::Command::new("/bin/sh")
                    .args(["-c", "exit 0"])
                    .status();
            }
        })
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("Ada");
    rt.block_on(Client::create_profile(&home, PASS, "Ada"))
        .unwrap();
    let mut refused = 0;
    for _ in 0..150 {
        match rt.block_on(Client::open(&home, PASS)) {
            Ok(c) => drop(c),
            Err(socketchat_core::error::CoreError::ProfileInUse) => refused += 1,
            Err(e) => panic!("{e}"),
        }
    }
    stop.store(true, Ordering::Relaxed);
    spawner.join().unwrap();
    assert_eq!(
        refused, 0,
        "a closed profile was reported in use {refused} times"
    );
}

#[test]
fn a_profile_open_in_another_app_is_still_refused() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("Ada");
    let open = rt
        .block_on(Client::create_profile(&home, PASS, "Ada"))
        .unwrap();
    let start = std::time::Instant::now();
    match rt.block_on(Client::open(&home, PASS)) {
        Err(socketchat_core::error::CoreError::ProfileInUse) => {}
        Ok(_) => panic!("a profile open in another app opened again"),
        Err(e) => panic!("{e}"),
    }
    let took = start.elapsed();
    assert!(
        took < std::time::Duration::from_secs(1),
        "the refusal took {took:?}"
    );
    drop(open);
}
