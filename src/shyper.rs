use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::fd::{AsRawFd, RawFd},
    sync::{Mutex, OnceLock},
};

pub struct ShyperBackend {
    file: Mutex<File>,
    fd: RawFd,
}

/// Singleton Module
static SHYPER_BACKEND: OnceLock<ShyperBackend> = OnceLock::new();

impl ShyperBackend {
    const SHYPER_BACKEND_PATH: &str = "/dev/shyper";

    fn get_instance() -> &'static Self {
        SHYPER_BACKEND.get_or_init(|| {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(Self::SHYPER_BACKEND_PATH)
                .unwrap_or_else(|err| panic!("{} open failed: {}", Self::SHYPER_BACKEND_PATH, err));
            let fd = file.as_raw_fd();
            Self {
                file: Mutex::new(file),
                fd,
            }
        })
    }

    pub fn fd() -> RawFd {
        Self::get_instance().fd
    }

    pub fn read(buf: &mut [u8]) -> std::io::Result<usize> {
        Self::get_instance().file.lock().unwrap().read(buf)
    }
}

#[macro_export]
macro_rules! shyper_ioctl {
    ($request : expr) => {
        libc::ioctl(crate::shyper::ShyperBackend::fd(), $request)
    };
    ($request : expr, $($arg:expr)*) => {
        libc::ioctl(crate::shyper::ShyperBackend::fd(), $request, $($arg)*)
    };
}
