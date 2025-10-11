use std::{
    fs::{File, OpenOptions},
    os::fd::{AsRawFd, RawFd},
    sync::OnceLock,
};

pub struct ShyperBackend {
    file: File,
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
            Self { file }
        })
    }

    pub fn fd() -> RawFd {
        Self::get_instance().file.as_raw_fd()
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
