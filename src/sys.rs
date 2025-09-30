// Copyright (c) 2023 Beihang University, Huawei Technologies Co.,Ltd. All rights reserved.
// Rust-Shyper is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::ffi::c_uint;

pub fn sys_reboot(force: bool) {
    unsafe {
        if shyper_ioctl!(0x0000, force as c_uint) != 0 {
            println!("err: ioctl fail!");
        }
    }
}

pub fn sys_shutdown(force: bool) {
    unsafe {
        if shyper_ioctl!(0x0001, force as c_uint) != 0 {
            println!("err: ioctl fail!");
        }
    }
}

pub fn sys_test() {
    unsafe {
        if shyper_ioctl!(0x0004, 0) != 0 {
            println!("err: ioctl fail!");
        }
    }
}

pub fn sys_update(_: String) {
    unimplemented!()
}
