use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use libloading::Library;

use crate::{
    config::Config,
    native::{self, NativeBundle},
};

type AioRegister = unsafe extern "C" fn(*const u16) -> i32;
type AioDial = unsafe extern "C" fn(i32, *const u16) -> i32;
type AioInit = unsafe extern "C" fn() -> i32;
type AioFree = unsafe extern "C" fn();

const AIO_FILTER_LOOPBACK: i32 = 0;
const AIO_FILTER_INTRANET: i32 = 1;
const AIO_FILTER_PARENT: i32 = 2;
const AIO_FILTER_ICMP: i32 = 3;
const AIO_FILTER_TCP: i32 = 4;
const AIO_FILTER_UDP: i32 = 5;
const AIO_FILTER_DNS: i32 = 6;
const AIO_DNS_ONLY: i32 = 8;
const AIO_DNS_PROXY: i32 = 9;
const AIO_TARGET_HOST: i32 = 12;
const AIO_TARGET_PORT: i32 = 13;
const AIO_TARGET_USER: i32 = 14;
const AIO_TARGET_PASS: i32 = 15;
const AIO_CLEAR_NAMES: i32 = 16;
const AIO_ADD_NAME: i32 = 17;
const AIO_BYPASS_NAME: i32 = 18;

pub struct RedirectorGuard {
    _library: Library,
    free: AioFree,
    active: bool,
}

impl RedirectorGuard {
    pub fn start(config: &Config) -> Result<Self> {
        config.validate_redirector()?;
        let bundle = native::verify_bundle(&config.redirector_dir)?;
        let installed = installed_driver_path(&config.driver_name)?;
        native::verify_component_at(&installed, bundle, "nfdriver.sys").with_context(|| {
            format!(
                "the installed driver is missing or incompatible; run 'procsocks driver install' from an Administrator console (expected {})",
                bundle.id
            )
        })?;
        let library = load_redirector(&config.redirector_dir)?;
        let dial = unsafe { *library.get::<AioDial>(b"aio_dial\0")? };
        let init = unsafe { *library.get::<AioInit>(b"aio_init\0")? };
        let free = unsafe { *library.get::<AioFree>(b"aio_free\0")? };

        set(dial, AIO_FILTER_LOOPBACK, "false")?;
        set(dial, AIO_FILTER_INTRANET, "false")?;
        set(dial, AIO_FILTER_PARENT, "false")?;
        set(dial, AIO_FILTER_ICMP, "false")?;
        set(dial, AIO_FILTER_TCP, "true")?;
        set(dial, AIO_FILTER_UDP, "false")?;
        set(dial, AIO_FILTER_DNS, "false")?;
        set(dial, AIO_DNS_ONLY, "false")?;
        set(dial, AIO_DNS_PROXY, "false")?;
        set(dial, AIO_TARGET_HOST, &config.listen.ip().to_string())?;
        set(dial, AIO_TARGET_PORT, &config.listen.port().to_string())?;
        set(dial, AIO_TARGET_USER, "")?;
        set(dial, AIO_TARGET_PASS, "")?;
        set(dial, AIO_CLEAR_NAMES, "")?;

        for pattern in &config.bypass_patterns {
            set(dial, AIO_BYPASS_NAME, pattern)
                .with_context(|| format!("invalid bypass regex {pattern:?}"))?;
        }
        if let Some(executable_name) = env::current_exe().ok().and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }) {
            set(dial, AIO_BYPASS_NAME, &executable_name)?;
        }
        for pattern in &config.process_patterns {
            set(dial, AIO_ADD_NAME, pattern)
                .with_context(|| format!("invalid process regex {pattern:?}"))?;
        }

        if unsafe { init() } == 0 {
            bail!(
                "redirector initialization failed; run as Administrator and ensure the '{}' driver is installed",
                config.driver_name
            );
        }

        Ok(Self {
            _library: library,
            free,
            active: true,
        })
    }

    pub fn probe(config: &Config) -> Result<&'static NativeBundle> {
        config.validate_redirector()?;
        let bundle = native::verify_bundle(&config.redirector_dir)?;
        let library = load_redirector(&config.redirector_dir)?;
        unsafe {
            let _ = library.get::<AioDial>(b"aio_dial\0")?;
            let _ = library.get::<AioInit>(b"aio_init\0")?;
            let _ = library.get::<AioFree>(b"aio_free\0")?;
        }
        Ok(bundle)
    }
}

impl Drop for RedirectorGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe { (self.free)() };
            self.active = false;
        }
    }
}

pub fn install_driver(config: &Config) -> Result<PathBuf> {
    config.validate_redirector()?;
    let bundle = native::verify_bundle(&config.redirector_dir)?;
    let source = config.redirector_dir.join("nfdriver.sys");
    if !source.is_file() {
        bail!("driver source is missing: {}", source.display());
    }
    let target = installed_driver_path(&config.driver_name)?;
    if target.exists() {
        native::verify_component_at(&target, bundle, "nfdriver.sys").with_context(|| {
            format!(
                "an incompatible driver already exists at {}; remove or upgrade it explicitly before installing",
                target.display()
            )
        })?;
    } else {
        fs::copy(&source, &target).with_context(|| {
            format!(
                "failed to copy driver from {} to {}; run as Administrator",
                source.display(),
                target.display()
            )
        })?;
        native::verify_component_at(&target, bundle, "nfdriver.sys")?;
    }

    if !service_exists(&config.driver_name) {
        let library = load_redirector(&config.redirector_dir)?;
        let register = unsafe { *library.get::<AioRegister>(b"aio_register\0")? };
        let name = wide(&config.driver_name);
        if unsafe { register(name.as_ptr()) } == 0 {
            bail!("failed to register driver service {}", config.driver_name);
        }
    }
    Ok(target)
}

pub fn import_components(
    source_directory: &Path,
    target_directory: &Path,
) -> Result<(String, Vec<PathBuf>)> {
    const COMPONENTS: [&str; 3] = ["Redirector.bin", "nfapi.dll", "nfdriver.sys"];
    let source_directory = source_directory.canonicalize().with_context(|| {
        format!(
            "failed to resolve native component source {}",
            source_directory.display()
        )
    })?;
    let source_bundle = native::verify_bundle(&source_directory)?;
    for component in COMPONENTS {
        let source = source_directory.join(component);
        if !source.is_file() {
            bail!("native component is missing: {}", source.display());
        }
    }

    fs::create_dir_all(target_directory).with_context(|| {
        format!(
            "failed to create native component directory {}",
            target_directory.display()
        )
    })?;
    let target_directory = target_directory.canonicalize().with_context(|| {
        format!(
            "failed to resolve native component directory {}",
            target_directory.display()
        )
    })?;
    if source_directory == target_directory {
        bail!("native component source and target directories are the same");
    }

    let mut imported = Vec::with_capacity(COMPONENTS.len());
    for component in COMPONENTS {
        let source = source_directory.join(component);
        let target = target_directory.join(component);
        fs::copy(&source, &target).with_context(|| {
            format!(
                "failed to copy native component from {} to {}",
                source.display(),
                target.display()
            )
        })?;
        imported.push(target);
    }
    let imported_bundle = native::verify_bundle(&target_directory)?;
    if imported_bundle.id != source_bundle.id {
        bail!("imported native bundle changed during copy");
    }
    Ok((imported_bundle.id.clone(), imported))
}

pub fn driver_status(config: &Config) -> Result<String> {
    let target = installed_driver_path(&config.driver_name)?;
    let output = Command::new("sc.exe")
        .args(["query", &config.driver_name])
        .output()
        .context("failed to execute sc.exe")?;
    let mut text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        text = String::from_utf8_lossy(&output.stderr).trim().to_string();
    }
    let (native_bundle, installed_driver) = match native::verify_bundle(&config.redirector_dir) {
        Ok(bundle) => {
            let installed = if target.is_file() {
                match native::verify_component_at(&target, bundle, "nfdriver.sys") {
                    Ok(()) => "verified".to_string(),
                    Err(error) => format!("mismatch ({error:#})"),
                }
            } else {
                "missing".to_string()
            };
            (format!("{} (verified)", bundle.id), installed)
        }
        Err(error) => (format!("unverified ({error:#})"), "not checked".to_string()),
    };
    Ok(format!(
        "native_bundle={native_bundle}\ndriver_file={}\ninstalled_driver={installed_driver}\nservice_exists={}\n{}",
        target.display(),
        output.status.success(),
        text
    ))
}

fn set(dial: AioDial, name: i32, value: &str) -> Result<()> {
    let value = wide(value);
    if unsafe { dial(name, value.as_ptr()) } == 0 {
        bail!("redirector rejected option {name}");
    }
    Ok(())
}

fn load_redirector(directory: &Path) -> Result<Library> {
    let path = directory.join("Redirector.bin");
    let previous = env::current_dir().context("failed to read current directory")?;
    env::set_current_dir(directory).with_context(|| {
        format!(
            "failed to enter redirector directory {}",
            directory.display()
        )
    })?;
    let result = unsafe { Library::new(&path) };
    let restore_result = env::set_current_dir(previous);
    restore_result.context("failed to restore current directory")?;
    result.with_context(|| format!("failed to load {}", path.display()))
}

fn installed_driver_path(driver_name: &str) -> Result<PathBuf> {
    let system_root = env::var_os("SystemRoot").context("SystemRoot is not defined")?;
    Ok(PathBuf::from(system_root)
        .join("System32")
        .join("drivers")
        .join(format!("{driver_name}.sys")))
}

fn service_exists(name: &str) -> bool {
    Command::new("sc.exe")
        .args(["query", name])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
