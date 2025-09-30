// Copyright (c) 2023 Beihang University, Huawei Technologies Co.,Ltd. All rights reserved.
// Rust-Shyper is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::{
    ffi::CStr,
    fs::File,
    io::{Read, Seek},
    mem,
};

use nix::unistd;

pub fn file_size(path: &String) -> Result<u64, String> {
    if let Ok(file) = File::open(&path) {
        if let Ok(metadata) = file.metadata() {
            Ok(metadata.len())
        } else {
            Err(format!("Get file {} metadata err", path))
        }
    } else {
        Err(format!("Open file {} err", path))
    }
}

pub fn cstr_arr_to_string(buf: &[u8]) -> String {
    let cstr = CStr::from_bytes_with_nul(buf).unwrap();
    cstr.to_str().unwrap().to_owned()
}

pub fn string_to_cstr_arr(s: String) -> [u8; 32] {
    let mut buf: [u8; 32] = [0; 32];
    let s = s.as_bytes();
    for i in 0..s.len() {
        buf[i] = s[i];
    }
    buf
}

// returns paddr
pub fn virt_to_phys_user(vaddr: u64) -> Result<u64, String> {
    let pagemap_path = "/proc/self/pagemap";
    let mut file =
        File::open(&pagemap_path).map_err(|err| format!("Open {} err: {}", &pagemap_path, err))?;

    let page_size = unistd::sysconf(unistd::SysconfVar::PAGE_SIZE)
        .unwrap()
        .unwrap() as usize;
    let offset = ((vaddr as usize) / page_size) * (mem::size_of::<*const ()>() as usize);

    if file.seek(std::io::SeekFrom::Start(offset as u64)).is_err() {
        return Err(format!(
            "File {} is not big enough to access offset {}",
            pagemap_path, offset
        ));
    }

    let mut entry = [0u8; 8];
    if file.read_exact(&mut entry).is_err() {
        return Err(format!("Read page table entry err"));
    }

    let pagemap_entry = u64::from_le_bytes(entry);
    if (pagemap_entry & (1 << 63)) == 0 {
        return Err(format!(
            "Virtual Address 0x{:#x} converts to paddr err: page not in memory",
            vaddr
        ));
    }

    // Note: 以下注释是pagemap_entry每一位的意义
    // entry->soft_dirty = (data >> 55) & 1;
    // entry->file_page = (data >> 61) & 1;
    // entry->swapped = (data >> 62) & 1;
    // entry->present = (data >> 63) & 1;

    let pfn = pagemap_entry & ((1 << 55) - 1);
    let paddr = pfn * (page_size as u64) + vaddr % (page_size as u64);
    Ok(paddr)
}

pub fn string_to_u64(s: String) -> Result<u64, std::num::ParseIntError> {
    let s = s.trim().to_string();
    let (src, radix) = if s.starts_with("0x") {
        (&s[2..], 16)
    } else if s.starts_with("0b") {
        (&s[2..], 2)
    } else {
        (s.as_str(), 10)
    };
    u64::from_str_radix(src, radix)
}
