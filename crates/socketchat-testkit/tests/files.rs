use std::path::{Path, PathBuf};

use socketchat_core::net::NetError;
use socketchat_core::CoreError;
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{settle, TestClient, TestServer};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

async fn pair(s: &TestServer) -> (GroupId, TestClient, TestClient) {
    let mut a = TestClient::new(s, "Ada").await;
    let g = a.create_group("Photos").await.unwrap();
    let mut b = TestClient::new(s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    (g, a, b)
}

/// Sends `path` from Ada and saves it on Bo's side.
async fn send_and_save(
    a: &mut TestClient,
    b: &mut TestClient,
    g: GroupId,
    path: &Path,
    video_ok: bool,
) -> Vec<u8> {
    a.send_file(g, path, video_ok).await.unwrap();
    settle(&mut [a, b]).await;
    let offer = b.files(g).pop().expect("Bo sees the file");
    let out = tempfile::tempdir().unwrap();
    let saved = b.save_file(g, offer.id, out.path()).await.unwrap();
    std::fs::read(saved).unwrap()
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn server_chunk_files(s: &TestServer) -> usize {
    let dir = s.dir.path().join("files");
    walk(&dir)
}

fn walk(p: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(p) else {
        return 0;
    };
    rd.map(|e| e.unwrap().path())
        .map(|p| if p.is_dir() { walk(&p) } else { 1 })
        .sum()
}

#[tokio::test]
async fn file_transfer_hash_checked() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("notes.bin");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&p, &data).unwrap();
    assert_eq!(send_and_save(&mut a, &mut b, g, &p, false).await, data);
    let offer = b.files(g).pop().unwrap();
    assert_eq!(offer.name, "notes.bin");
    assert_eq!(offer.size, 300_000);
    let line = b
        .messages(g, 10)
        .into_iter()
        .find(|l| l.text.contains("notes.bin"))
        .unwrap();
    assert!(line.notice, "file lines read as notices: {line:?}");
    assert_eq!(line.text, "Ada sent notes.bin (300 KB)");
}

#[tokio::test]
async fn exif_removed_from_jpeg_png_webp() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    for (f, header) in [
        ("gps.jpg", &b"\xff\xd8\xff"[..]),
        ("gps.png", &b"\x89PNG"[..]),
        ("gps.webp", &b"RIFF"[..]),
    ] {
        let original = std::fs::read(fixture(f)).unwrap();
        assert!(
            has(&original, b"SecretPhoneModel"),
            "fixture {f} carries metadata"
        );
        let got = send_and_save(&mut a, &mut b, g, &fixture(f), false).await;
        assert!(got.starts_with(header), "{f} is still that kind of image");
        assert!(
            !has(&got, b"SecretPhoneModel"),
            "{f} lost its device and location data"
        );
        assert!(!has(&got, b"Exif\0\0"), "{f} has no EXIF block");
    }
}

#[tokio::test]
async fn send_file_says_which_files_were_cleaned() {
    let s = TestServer::start().await;
    let (g, mut a, _b) = pair(&s).await;
    for f in ["gps.jpg", "gps.png", "gps.webp"] {
        let offer = a.send_file(g, &fixture(f), false).await.unwrap();
        assert_eq!(offer.name, f);
        assert!(offer.metadata_removed(), "{f}");
    }
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("notes.txt");
    std::fs::write(&p, b"plain text").unwrap();
    let offer = a.send_file(g, &p, false).await.unwrap();
    assert!(!offer.metadata_removed(), "other files go as they are");
    let offer = a.send_file(g, &fixture("clip.mp4"), true).await.unwrap();
    assert!(!offer.metadata_removed(), "a video keeps its own data");
}

#[tokio::test]
async fn video_needs_confirm_then_sends() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let err = a
        .send_file(g, &fixture("clip.mp4"), false)
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::VideoNeedsConfirm), "{err:?}");
    settle(&mut [&mut a, &mut b]).await;
    assert!(b.files(g).is_empty());
    let got = send_and_save(&mut a, &mut b, g, &fixture("clip.mp4"), true).await;
    assert_eq!(got, std::fs::read(fixture("clip.mp4")).unwrap());
}

#[tokio::test]
async fn tampered_chunk_detected() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("doc.txt");
    std::fs::write(&p, vec![b'a'; 100_000]).unwrap();
    a.send_file(g, &p, false).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    // Someone with the server's disk flips one byte of the first chunk.
    let chunk = std::fs::read_dir(s.dir.path().join("files"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("0");
    let mut bytes = std::fs::read(&chunk).unwrap();
    bytes[10] ^= 1;
    std::fs::write(&chunk, bytes).unwrap();
    let offer = b.files(g).pop().unwrap();
    let out = tempfile::tempdir().unwrap();
    assert!(b.save_file(g, offer.id, out.path()).await.is_err());
    assert_eq!(
        std::fs::read_dir(out.path()).unwrap().count(),
        0,
        "nothing half-written is left"
    );
}

#[tokio::test]
async fn saved_names_never_overwrite_or_escape() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("report.txt");
    std::fs::write(&p, b"v1").unwrap();
    a.send_file(g, &p, false).await.unwrap();
    std::fs::write(&p, b"v2").unwrap();
    a.send_file(g, &p, false).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let out = tempfile::tempdir().unwrap();
    let mut saved = vec![];
    for f in b.files(g) {
        saved.push(b.save_file(g, f.id, out.path()).await.unwrap());
    }
    let names: Vec<String> = saved
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into())
        .collect();
    assert_eq!(names, vec!["report.txt", "report (1).txt"]);
    assert!(saved.iter().all(|p| p.parent() == Some(out.path())));
}

#[tokio::test]
async fn server_deletes_file_after_all_done() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("x.bin");
    std::fs::write(&p, vec![1u8; 150_000]).unwrap();
    a.send_file(g, &p, false).await.unwrap();
    assert_eq!(server_chunk_files(&s), 3);
    settle(&mut [&mut a, &mut b]).await;
    let offer = b.files(g).pop().unwrap();
    let out = tempfile::tempdir().unwrap();
    b.save_file(g, offer.id, out.path()).await.unwrap();
    assert_eq!(server_chunk_files(&s), 0);
}

#[tokio::test]
async fn oversize_file_refused_before_upload() {
    let s = TestServer::start_with(|c| c.max_file_mb = 1).await;
    let (g, mut a, _b) = pair(&s).await;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("big.bin");
    std::fs::write(&p, vec![0u8; 2_000_000]).unwrap();
    let err = a.send_file(g, &p, false).await.unwrap_err();
    assert!(
        matches!(err, CoreError::Net(NetError::Refused(ref m)) if m.contains("1 MB")),
        "{err:?}"
    );
    assert_eq!(server_chunk_files(&s), 0);
}
