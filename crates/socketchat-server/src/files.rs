//! Sealed file chunks. The server stores them as files on disk and hands
//! them to members; it never holds the key that opens them.

use std::path::PathBuf;

use rusqlite::{params, OptionalExtension};
use socketchat_proto::msg::{FileId, GroupId as Gid, Key, Response};

use crate::conn::ConnState;
use crate::groups::{joined_keys, member_key};
use crate::State;

/// Plaintext bytes per chunk, plus the 16-byte tag the cipher adds.
const MAX_CHUNK: usize = 64 * 1024 + 16;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn file_dir(state: &State, id: &FileId) -> PathBuf {
    state.cfg.data_dir.join("files").join(hex(&id.0))
}

fn chunk_count(size: u64) -> u64 {
    size.div_ceil(64 * 1024).max(1)
}

struct FileRow {
    group: Gid,
    size: u64,
    chunks: u64,
    complete: bool,
    uploader: Vec<u8>,
}

fn load(db: &rusqlite::Connection, id: &FileId) -> Option<FileRow> {
    db.query_row(
        "SELECT group_id, size, chunks, complete, uploader FROM files WHERE id = ?1",
        [id.0.as_slice()],
        |r| {
            let g: Vec<u8> = r.get(0)?;
            Ok(FileRow {
                group: Gid(g.try_into().unwrap_or([0; 16])),
                size: r.get::<_, i64>(1)? as u64,
                chunks: r.get::<_, i64>(2)? as u64,
                complete: r.get(3)?,
                uploader: r.get(4)?,
            })
        },
    )
    .optional()
    .ok()
    .flatten()
}

pub fn begin(state: &State, cs: &ConnState, group: Gid, size: u64) -> Response {
    let limit = state.cfg.max_file_mb;
    if size > limit * 1_000_000 {
        return Response::Refused(format!(
            "this file is larger than this server's limit of {limit} MB"
        ));
    }
    let db = state.db();
    let Some(me) = member_key(&db, cs, &group) else {
        return Response::Refused("you are not a member of this group".into());
    };
    let id = FileId(crate::random_token().0);
    let ok = db.execute(
        "INSERT INTO files (id, group_id, size, uploader, created_unix) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id.0.as_slice(),
            group.0.as_slice(),
            size as i64,
            me.0.as_slice(),
            state.now() as i64
        ],
    );
    if ok.is_err() {
        return Response::Error("could not start the upload".into());
    }
    Response::File(id)
}

pub fn chunk(state: &State, cs: &ConnState, file: FileId, index: u32, data: &[u8]) -> Response {
    if data.len() > MAX_CHUNK {
        return Response::Refused("that chunk is too large".into());
    }
    let db = state.db();
    let Some(f) = load(&db, &file) else {
        return Response::Refused("no such upload".into());
    };
    if !cs
        .proven
        .iter()
        .any(|k| k.0.as_slice() == f.uploader.as_slice())
    {
        return Response::Refused("only the sender can upload this file".into());
    }
    if f.complete || index as u64 != f.chunks || f.chunks >= chunk_count(f.size) {
        return Response::Refused("chunks must arrive in order and within the file's size".into());
    }
    drop(db);
    let dir = file_dir(state, &file);
    if std::fs::create_dir_all(&dir)
        .and_then(|_| std::fs::write(dir.join(index.to_string()), data))
        .is_err()
    {
        return Response::Error("could not store the chunk".into());
    }
    let db = state.db();
    let _ = db.execute(
        "UPDATE files SET chunks = chunks + 1 WHERE id = ?1",
        [file.0.as_slice()],
    );
    Response::Ok
}

pub fn end(state: &State, cs: &ConnState, file: FileId) -> Response {
    let db = state.db();
    let Some(f) = load(&db, &file) else {
        return Response::Refused("no such upload".into());
    };
    if !cs
        .proven
        .iter()
        .any(|k| k.0.as_slice() == f.uploader.as_slice())
    {
        return Response::Refused("only the sender can finish this upload".into());
    }
    if f.chunks != chunk_count(f.size) {
        return Response::Refused("some chunks are missing".into());
    }
    let _ = db.execute(
        "UPDATE files SET complete = 1 WHERE id = ?1",
        [file.0.as_slice()],
    );
    Response::Ok
}

pub fn get(state: &State, cs: &ConnState, file: FileId, index: u32) -> Response {
    let db = state.db();
    let Some(f) = load(&db, &file) else {
        return Response::Refused("this file is no longer on the server".into());
    };
    if member_key(&db, cs, &f.group).is_none() {
        return Response::Refused("you are not a member of this group".into());
    }
    if !f.complete || index as u64 >= f.chunks {
        return Response::Refused("that part of the file is not here".into());
    }
    drop(db);
    match std::fs::read(file_dir(state, &file).join(index.to_string())) {
        Ok(b) => Response::Chunk(b),
        Err(_) => Response::Error("could not read the chunk".into()),
    }
}

/// Deletes a file's chunks and records.
pub(crate) fn delete(state: &State, db: &rusqlite::Connection, file: &FileId) {
    let _ = std::fs::remove_dir_all(file_dir(state, file));
    let _ = db.execute("DELETE FROM files WHERE id = ?1", [file.0.as_slice()]);
    let _ = db.execute(
        "DELETE FROM file_done WHERE file_id = ?1",
        [file.0.as_slice()],
    );
}

/// A member has the file. Once every member but the sender does, it goes.
pub fn done(state: &State, cs: &ConnState, file: FileId) -> Response {
    let db = state.db();
    let Some(f) = load(&db, &file) else {
        return Response::Ok;
    };
    let Some(me) = member_key(&db, cs, &f.group) else {
        return Response::Refused("you are not a member of this group".into());
    };
    let _ = db.execute(
        "INSERT OR IGNORE INTO file_done (file_id, mailbox) VALUES (?1, ?2)",
        params![file.0.as_slice(), me.0.as_slice()],
    );
    let waiting: Vec<Key> = joined_keys(&db, &f.group)
        .into_iter()
        .filter(|k| k.0.as_slice() != f.uploader.as_slice())
        .filter(|k| {
            !db.query_row(
                "SELECT EXISTS(SELECT 1 FROM file_done WHERE file_id = ?1 AND mailbox = ?2)",
                params![file.0.as_slice(), k.0.as_slice()],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false)
        })
        .collect();
    if waiting.is_empty() {
        delete(state, &db, &file);
    }
    Response::Ok
}
