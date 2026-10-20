//! Memory budget for a large file. This test has a binary of its own: the
//! counting allocator below sees every allocation in the process, so another
//! test running beside it (each new profile's Argon2 key derivation alone
//! takes about 19 MiB) would show up in the measurement.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use socketchat_proto::msg::GroupId;
use socketchat_testkit::{settle, TestClient, TestServer};

/// Tracks live heap bytes and the peak, so a test can bound memory use.
struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static A: Counting = Counting;

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

#[tokio::test]
async fn large_file_memory_budget() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("movie.bin");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&p).unwrap();
        let block: Vec<u8> = (0..1_048_576u32).map(|i| (i % 253) as u8).collect();
        for _ in 0..64 {
            f.write_all(&block).unwrap();
        }
    }
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    a.send_file(g, &p, false).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let offer = b.files(g).pop().unwrap();
    let out = tempfile::tempdir().unwrap();
    let saved = b.save_file(g, offer.id, out.path()).await.unwrap();
    let grew = PEAK.load(Ordering::Relaxed).saturating_sub(base);
    assert_eq!(std::fs::metadata(saved).unwrap().len(), 64 * 1_048_576);
    println!("peak heap grew by {grew} bytes while sending and saving 64 MiB");
    assert!(grew < 8 * 1_048_576, "peak heap grew by {grew} bytes");
}
