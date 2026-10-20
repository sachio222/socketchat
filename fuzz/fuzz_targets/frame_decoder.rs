#![no_main]

use libfuzzer_sys::fuzz_target;
use socketchat_proto::msg::{from_body, ClientFrame, ServerFrame};
use socketchat_proto::FrameDecoder;

// Bytes from the network must never crash either side.
fuzz_target!(|data: &[u8]| {
    let mut d = FrameDecoder::default();
    d.push(data);
    while let Ok(Some(body)) = d.next_frame() {
        let _ = from_body::<ClientFrame>(&body);
        let _ = from_body::<ServerFrame>(&body);
    }
});
