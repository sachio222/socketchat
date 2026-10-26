//! Sending the files dropped in the message box, as `/send` sends them.

use std::path::Path;

use socketchat_core::files::{fill, sniff, Kind, CLEANED, MAX_PHOTO_BYTES};
use socketchat_core::CoreError;
use socketchat_proto::msg::GroupId;

use super::{Screen, UNREACHABLE_LEAD};
use crate::app::{cleaned_status, not_sent, sendable, Attachment, DropKind, Modal};

/// Whether `/send` asks before sending this file as it is: a video, a
/// photo Socketchat cannot clean, or one too big to clean.
fn asks_first(path: &Path, size: u64) -> bool {
    let mut head = [0u8; 16];
    let n = std::fs::File::open(path)
        .and_then(|mut f| fill(&mut f, &mut head))
        .unwrap_or(0);
    let kind = sniff(&head[..n]);
    matches!(kind, Kind::Video | Kind::OtherPhoto)
        || (CLEANED.contains(&kind) && size > MAX_PHOTO_BYTES)
}

impl Screen {
    /// Sends the dropped files in the order their placeholders show, then
    /// the words left in the message box as a message. Each file's
    /// placeholder leaves the box as it goes. Nothing goes while a file
    /// has gone or cannot be read, or before the person says yes to each
    /// video and each photo Socketchat cannot clean.
    pub(super) async fn send_drop(&mut self, g: GroupId) -> Result<(), String> {
        let files = self.app.attachments();
        let mut sizes = vec![];
        for a in &files {
            sizes.push(sendable(&a.path).map_err(|why| not_sent(a, why))?);
        }
        if let Some(a) = files
            .iter()
            .zip(&sizes)
            .find(|(a, size)| !a.as_is && asks_first(&a.path, **size))
            .map(|(a, _)| a)
        {
            self.ask_as_is(g, a);
            return Ok(());
        }
        let mut cleaned = vec![];
        for a in &files {
            match self.client.send_file(g, &a.path, a.as_is).await {
                Ok(offer) => {
                    self.app.first_attachment_sent();
                    if offer.metadata_removed() {
                        cleaned.push(offer.name);
                    }
                }
                // A photo found too damaged to clean as it went.
                Err(CoreError::VideoNeedsConfirm | CoreError::PhotoNeedsConfirm) => {
                    self.ask_as_is(g, a);
                    return Ok(());
                }
                Err(e) => {
                    let e = e.to_string();
                    if e.starts_with(UNREACHABLE_LEAD) || !self.client.connected() {
                        return Err(e);
                    }
                    return Err(format!("{}, {}, was not sent: {e}", a.title(), a.name));
                }
            }
        }
        self.app.status = cleaned_status(&cleaned);
        let text = self.app.take_dropped_text();
        if text.is_empty() {
            return Ok(());
        }
        self.send_text(g, text).await
    }

    /// The question `/send` asks before sending a video, or a photo it
    /// cannot clean, as it is.
    fn ask_as_is(&mut self, group: GroupId, a: &Attachment) {
        let path = a.path.display().to_string();
        self.app.modal = Some(match a.kind {
            DropKind::Video => Modal::ConfirmVideo { group, path },
            _ => Modal::ConfirmPhoto { group, path },
        });
    }
}
