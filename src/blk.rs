// Copyright (c) 2023 Beihang University, Huawei Technologies Co.,Ltd. All rights reserved.
// Rust-Shyper is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use libc::{
    c_uint, c_void, mmap, size_t, MAP_ANONYMOUS, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE,
    S_IFBLK, S_IFMT,
};
use nix::{
    fcntl::{open, OFlag},
    sys::{stat::Mode, uio},
};
use once_cell::sync::OnceCell;
use std::{
    fs,
    os::{
        fd::{BorrowedFd, RawFd},
        linux::fs::MetadataExt,
    },
    process::Command,
    slice,
    sync::Mutex,
};

use crate::{
    daemon::generate_hvc_mode,
    ioctl_arg::{IOCTL_SYS, IOCTL_SYS_APPEND_MED_BLK},
    util::{cstr_arr_to_string, string_to_cstr_arr, virt_to_phys_user},
};

pub const HUGE_TLB_MAX: usize = 32 * 1024 * 1024;
pub const BLOCK_SIZE: usize = 512;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct MediatedBlkCfg {
    name: [u8; 32],
    block_dev_path: [u8; 32],
    block_num: u64,
    dma_block_max: u64,
    cache_size: u64,
    idx: u16,
    pcache: bool,
    cache_va: u64,
    cache_ipa: u64,
    cache_pa: u64,
}

// Set this only once in the config_daemon
pub static MED_BLK_LIST: OnceCell<Vec<MediatedBlkCfg>> = OnceCell::new();
static IMG_FILE_FDS: Mutex<Vec<RawFd>> = Mutex::new(Vec::new());

// Read the count blocks of the blk id starting from the lba sector
// Note: do not exceed cache_size!
#[inline(always)]
fn blk_read(blk_id: u16, lba: u64, mut count: u64) {
    let binding = MED_BLK_LIST.get().unwrap();
    let blk_cfg = binding.get(blk_id as usize).unwrap();
    let binding2 = IMG_FILE_FDS.lock().unwrap();
    let img_file = binding2.get(blk_id as usize).unwrap();

    let fd = unsafe { BorrowedFd::borrow_raw(*img_file) };

    if count > blk_cfg.dma_block_max {
        warn!(
            "blk_read count {} > dma_block_max {}, shrink count to {}",
            count, blk_cfg.dma_block_max, blk_cfg.dma_block_max
        );
        count = blk_cfg.dma_block_max;
    }

    let buf = unsafe {
        slice::from_raw_parts_mut(blk_cfg.cache_va as *mut u8, count as usize * BLOCK_SIZE)
    };

    match uio::pread(fd, buf, lba as i64 * BLOCK_SIZE as i64) {
        Ok(read_len) => {
            if read_len != (count as usize * BLOCK_SIZE) {
                warn!(
                    "read lba {:#x} size {:#x} failed! read_len = {:#x}",
                    lba,
                    count * BLOCK_SIZE as u64,
                    read_len
                );
            }
        }
        Err(err) => warn!(
            "read lba {:#x} size {:#x} failed: {}!",
            lba,
            count * BLOCK_SIZE as u64,
            err
        ),
    }
}

fn blk_write(blk_id: u16, lba: u64, mut count: u64) {
    let binding = MED_BLK_LIST.get().unwrap();
    let blk_cfg = binding.get(blk_id as usize).unwrap();
    let binding2 = IMG_FILE_FDS.lock().unwrap();
    let img_file = binding2.get(blk_id as usize).unwrap();

    let fd = unsafe { BorrowedFd::borrow_raw(*img_file) };

    if count > blk_cfg.dma_block_max {
        warn!(
            "blk_write count {} > dma_block_max {}, shrink count to {}",
            count, blk_cfg.dma_block_max, blk_cfg.dma_block_max
        );
        count = blk_cfg.dma_block_max;
    }

    let buf =
        unsafe { slice::from_raw_parts(blk_cfg.cache_va as *mut u8, count as usize * BLOCK_SIZE) };

    match uio::pwrite(fd, buf, lba as i64 * BLOCK_SIZE as i64) {
        Ok(write_len) => {
            if write_len != (count as usize * BLOCK_SIZE) {
                warn!(
                    "write lba {:#x} size {:#x} failed! write_len = {:#x}",
                    lba,
                    count * BLOCK_SIZE as u64,
                    write_len
                );
            }
        }
        Err(err) => warn!(
            "write lba {:#x} size {:#x} failed: {}!",
            lba,
            count * BLOCK_SIZE as u64,
            err
        ),
    }
}

// Read/write sector 0 of the disk to test whether the disk is ready
fn blk_try_rw(blk_id: u16) -> Result<(), String> {
    let mut origin_data = [0; BLOCK_SIZE];
    let binding = MED_BLK_LIST.get().unwrap();
    let blk = binding.get(blk_id as usize).unwrap();

    let cache = unsafe { slice::from_raw_parts_mut(blk.cache_va as *mut u8, BLOCK_SIZE) };

    // Read origin data, and save it in origin_data
    blk_read(blk_id, 0, 1);
    origin_data.clone_from_slice(cache);

    for (i, mem) in cache.iter_mut().enumerate() {
        *mem = (i % 256) as u8
    }
    blk_write(blk_id, 0, 1);

    cache.fill(0);
    blk_read(blk_id, 0, 1);

    // Check if the data written before is read correctly
    for (i, mem) in cache.iter().enumerate() {
        if *mem != (i % 256) as u8 {
            return Err(format!("blk {} read write test failed!", blk_id));
        }
    }

    cache.clone_from_slice(&origin_data);

    // Written back
    blk_write(blk_id, 0, 1);
    Ok(())
}

pub fn mediated_blk_init() {
    // Kernel boot options cmdline:
    // default_hugepagesz=32M hugepagesz=32M hugepages=1
    // mount hugetlbfs
    // mkdir /mnt/huge
    // mount -t hugetlbfs -o pagesize=32M none /mnt/huge
    let med_blk_list = MED_BLK_LIST.get().expect("med_blk_list is None");
    let mut img_file_fds = IMG_FILE_FDS.lock().unwrap();
    if med_blk_list.is_empty() {
        warn!("NO mediated block device!");
    }

    for _ in 0..med_blk_list.len() {
        img_file_fds.push(-1);
    }

    let output = Command::new("mkdir")
        .arg("-p")
        .arg("/mnt/huge")
        .output()
        .expect("failed to execute mkdir");

    if !output.status.success() {
        warn!("mkdir /mnt/huge failed");
        return;
    }

    let output = Command::new("mount")
        .arg("-t")
        .arg("hugetlbfs")
        .arg("-o")
        .arg("pagesize=32M")
        .arg("none")
        .arg("/mnt/huge")
        .output()
        .expect("failed to execute mount");

    if !output.status.success() {
        warn!("mount hugetlbfs failed");
        return;
    }

    for i in 0..med_blk_list.len() {
        let cache_size = med_blk_list[i].cache_size;
        let block_dev_path = cstr_arr_to_string(med_blk_list[i].block_dev_path.as_slice());
        let name = cstr_arr_to_string(med_blk_list[i].name.as_slice());
        info!(
            "Shyper daemon init blk {} with cache size {}",
            name, cache_size
        );

        info!(
            "Shyper daemon init blk {} va {:#x} with cache pa {:#x}",
            name, med_blk_list[i].cache_va as u64, med_blk_list[i].cache_ipa as u64
        );

        match open(
            block_dev_path.as_str(),
            OFlag::O_RDWR | OFlag::O_DIRECT,
            Mode::empty(),
        ) {
            Ok(fd) => img_file_fds[i] = fd,
            Err(err) => {
                warn!("open block device {} failed: {}", block_dev_path, err);
                return;
            }
        }

        // block_try_rw
        if let Err(err) = blk_try_rw(i as u16) {
            warn!("blk_try_rw failed: {}", err);
            return;
        }

        let request = generate_hvc_mode(IOCTL_SYS, IOCTL_SYS_APPEND_MED_BLK);
        unsafe {
            if shyper_ioctl!(
                request as u64,
                &med_blk_list[i] as *const MediatedBlkCfg as *mut c_void
            ) != 0
            {
                warn!("ioctl append mediated blk failed");
                return;
            }
        }

        info!(
            "Shyper daemon init blk {} success",
            cstr_arr_to_string(med_blk_list[i].name.clone().as_slice())
        );
    }
}

// mediated_blk_read: Do reading, and after that send finishing signal to kernel module
pub fn mediated_blk_read(blk_id: u16, lba: u64, count: u64) {
    blk_read(blk_id, lba, count);

    let ret = unsafe { shyper_ioctl!(0x0331, blk_id as c_uint) };
    if ret != 0 {
        warn!("Mediated blk read ioctl failed");
    }
}

pub fn mediated_blk_write(blk_id: u16, lba: u64, count: u64) {
    blk_write(blk_id, lba, count);

    let ret = unsafe { shyper_ioctl!(0x0331, blk_id as c_uint) };
    if ret != 0 {
        warn!("Mediated blk read ioctl failed");
    }
}

// Add a mediated blk
pub fn mediated_blk_add(index: usize, dev: String) -> Result<MediatedBlkCfg, String> {
    let metadata = fs::metadata(dev.clone()).map_err(|x| format!("metadata err: {}", x))?;

    let file_type = metadata.st_mode() & (S_IFMT as u32);
    if file_type != S_IFBLK {
        warn!(
            "{} is not a block device, but we can also use {} as a img file",
            dev, dev
        );
    }

    let ctx = fdisk::Context::new();
    ctx.assign_device(dev.clone(), true)
        .map_err(|dev| format!("assign device {} err", dev))?;

    let nsec = ctx.logical_sectors();
    info!(
        "Shyper daemon add blk {} with {} sectors",
        dev.clone(),
        nsec
    );

    let cache_va;
    let cache_size = HUGE_TLB_MAX as u64;
    unsafe {
        cache_va = mmap(
            0 as *mut c_void,
            cache_size as size_t,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
            0,
            0,
        );
        if cache_va == libc::MAP_FAILED {
            warn!("mmap cache failed");
            return Err("mmap cache failed".to_string());
        }
    }

    let phys_result = virt_to_phys_user(cache_va as u64);
    if let Err(err) = phys_result {
        warn!("virt_to_phys_user failed: {}", err);
        return Err(format!("virt_to_phys_user failed: {}", err));
    }

    let cfg = MediatedBlkCfg {
        name: string_to_cstr_arr(format!("MEDBLK{}", index)),
        block_dev_path: string_to_cstr_arr(dev.clone()),
        block_num: nsec,
        dma_block_max: cache_size / BLOCK_SIZE as u64,
        cache_size,
        idx: index as u16,
        pcache: false,
        cache_va: cache_va as u64,
        cache_ipa: phys_result.unwrap(),
        cache_pa: 0,
    };
    ctx.deassign_device(false)
        .map_err(|x| format!("deassign device {} err: {}", dev, x))?;

    Ok(cfg)
}
