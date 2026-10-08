//! Opening a file costs about 20 µs on Windows, mostly in filesystem filter
//! drivers. `std`'s listing avoids that but omits file IDs, so `read_dir`
//! uses the listing call that includes them.

use super::{Entry, Kind, Stat, StatKey};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::mem::offset_of;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE};
use windows::Win32::Storage::FileSystem::{
    FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo, FileIdInfo,
    GetFileInformationByHandleEx, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_EXTD_DIR_INFO, FILE_ID_INFO,
    FILE_INFO_BY_HANDLE_CLASS,
};

/// 100 ns intervals between 1601-01-01 (FILETIME) and 1970-01-01.
const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// Opens the file again: `std` metadata carries no 128-bit file ID. A
/// symlink is identified as itself, as in the listing.
pub(super) fn file_id(path: &Path, md: &fs::Metadata) -> io::Result<(u64, u128)> {
    let mut flags = FILE_FLAG_BACKUP_SEMANTICS.0;
    if md.file_type().is_symlink() {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT.0;
    }
    // No access rights: like `fs::metadata`, this works on files open elsewhere.
    let file = OpenOptions::new()
        .access_mode(0)
        .custom_flags(flags)
        .open(path)?;
    let info = id_info(&file)?;
    Ok((
        info.VolumeSerialNumber,
        u128::from_le_bytes(info.FileId.Identifier),
    ))
}

/// Windows attributes are not permissions; backup software flips them.
pub(super) fn mode(_md: &fs::Metadata) -> u32 {
    0
}

pub(super) fn read_dir(dir: &Path) -> io::Result<Vec<Entry>> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(dir)?;
    let volume = id_info(&directory)?.VolumeSerialNumber;
    // u64 elements keep the buffer 8-byte aligned, as the records require.
    let mut buffer = vec![0u64; 8192];
    let mut class = FileIdExtdDirectoryRestartInfo;
    let mut entries = Vec::new();
    loop {
        match query(
            &directory,
            class,
            buffer.as_mut_ptr().cast(),
            buffer.len() * 8,
        ) {
            Err(error) if error.raw_os_error() == Some(ERROR_NO_MORE_FILES.0 as i32) => break,
            result => result?,
        }
        class = FileIdExtdDirectoryInfo;
        let bytes = buffer.as_ptr().cast::<u8>();
        let mut offset = 0;
        loop {
            // SAFETY: the call above filled the buffer with a chain of records,
            // each starting at its predecessor's NextEntryOffset. Some drivers
            // misalign records, so read them unaligned.
            let (info, name) = unsafe {
                let record = bytes.add(offset);
                let info = record.cast::<FILE_ID_EXTD_DIR_INFO>().read_unaligned();
                let name = record
                    .add(offset_of!(FILE_ID_EXTD_DIR_INFO, FileName))
                    .cast::<u16>();
                let name: Vec<u16> = (0..info.FileNameLength as usize / 2)
                    .map(|i| name.add(i).read_unaligned())
                    .collect();
                (info, name)
            };
            if name != [b'.' as u16] && name != [b'.' as u16, b'.' as u16] {
                entries.push(entry(&info, name, volume));
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            offset += info.NextEntryOffset as usize;
        }
    }
    Ok(entries)
}

fn entry(info: &FILE_ID_EXTD_DIR_INFO, name: Vec<u16>, volume: u64) -> Entry {
    let attributes = info.FileAttributes;
    // The same classification as std: name-surrogate reparse points
    // (symlinks and junctions) are links; other reparse points are files.
    let kind = if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        && info.ReparsePointTag & 0x2000_0000 != 0
    {
        Kind::Symlink
    } else if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        Kind::Directory
    } else {
        Kind::File
    };
    Entry {
        name: std::ffi::OsString::from_wide(&name),
        stat: Stat {
            kind,
            mode: 0,
            // Identical to `super::key` for the same file.
            key: StatKey {
                size: info.EndOfFile as u64,
                modified_ns: i128::from(info.LastWriteTime - UNIX_EPOCH_TICKS) * 100,
                id: (volume, u128::from_le_bytes(info.FileId.Identifier)),
            },
        },
    }
}

/// The volume serial number and 128-bit file ID of an open file.
fn id_info(file: &File) -> io::Result<FILE_ID_INFO> {
    let mut info = FILE_ID_INFO::default();
    query(file, FileIdInfo, (&raw mut info).cast(), size_of_val(&info))?;
    Ok(info)
}

fn query(
    file: &File,
    class: FILE_INFO_BY_HANDLE_CLASS,
    buffer: *mut std::ffi::c_void,
    size: usize,
) -> io::Result<()> {
    // SAFETY: `buffer` points to `size` writable bytes owned by the caller.
    unsafe {
        GetFileInformationByHandleEx(HANDLE(file.as_raw_handle()), class, buffer, size as u32)
    }
    .map_err(|error| io::Error::from_raw_os_error(error.code().0 & 0xFFFF))
}
