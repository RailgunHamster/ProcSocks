use std::{fs, path::Path, sync::OnceLock};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const LOCK_FILE: &str = include_str!("../native-components.lock.json");
const REQUIRED_COMPONENTS: [&str; 3] = ["Redirector.bin", "nfapi.dll", "nfdriver.sys"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeManifest {
    schema_version: u32,
    bundles: Vec<NativeBundle>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeBundle {
    pub id: String,
    architecture: String,
    components: Vec<NativeComponent>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeComponent {
    name: String,
    #[allow(dead_code)]
    file_version: Option<String>,
    size: u64,
    sha256: String,
}

#[derive(Debug)]
struct Fingerprint {
    size: u64,
    sha256: String,
}

pub fn verify_bundle(directory: &Path) -> Result<&'static NativeBundle> {
    if std::env::consts::ARCH != "x86_64" {
        bail!(
            "the locked native redirector bundle supports x86_64 only; current architecture is {}",
            std::env::consts::ARCH
        );
    }

    let mut actual = Vec::with_capacity(REQUIRED_COMPONENTS.len());
    for name in REQUIRED_COMPONENTS {
        let path = directory.join(name);
        actual.push((name, fingerprint(&path)?));
    }

    for bundle in &manifest().bundles {
        if bundle.architecture != std::env::consts::ARCH {
            continue;
        }
        let matches = actual.iter().all(|(name, fingerprint)| {
            bundle
                .components
                .iter()
                .find(|component| component.name == *name)
                .is_some_and(|component| component_matches(component, fingerprint))
        });
        if matches {
            return Ok(bundle);
        }
    }

    let actual = actual
        .iter()
        .map(|(name, fingerprint)| {
            format!(
                "  {name}: size={} sha256={}",
                fingerprint.size, fingerprint.sha256
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let supported = manifest()
        .bundles
        .iter()
        .map(|bundle| format!("  {}", bundle.id))
        .collect::<Vec<_>>()
        .join("\n");
    bail!(
        "native redirector files do not match a tested bundle; do not mix files from different releases\nactual:\n{actual}\nsupported:\n{supported}"
    )
}

pub fn verify_component_at(path: &Path, bundle: &NativeBundle, component_name: &str) -> Result<()> {
    let expected = bundle
        .components
        .iter()
        .find(|component| component.name == component_name)
        .with_context(|| {
            format!(
                "bundle {} does not declare component {component_name}",
                bundle.id
            )
        })?;
    let actual = fingerprint(path)?;
    if !component_matches(expected, &actual) {
        bail!(
            "{} does not match bundle {}: size={} sha256={}",
            path.display(),
            bundle.id,
            actual.size,
            actual.sha256
        );
    }
    Ok(())
}

fn component_matches(expected: &NativeComponent, actual: &Fingerprint) -> bool {
    expected.size == actual.size && expected.sha256.eq_ignore_ascii_case(&actual.sha256)
}

fn fingerprint(path: &Path) -> Result<Fingerprint> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read native component {}", path.display()))?;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    Ok(Fingerprint {
        size: bytes.len() as u64,
        sha256,
    })
}

fn manifest() -> &'static NativeManifest {
    static MANIFEST: OnceLock<NativeManifest> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        let manifest: NativeManifest = serde_json::from_str(LOCK_FILE)
            .expect("native-components.lock.json must be valid JSON");
        assert_eq!(
            manifest.schema_version, 1,
            "unsupported native component lock schema"
        );
        assert!(
            !manifest.bundles.is_empty(),
            "native component lock must contain a bundle"
        );
        manifest
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{REQUIRED_COMPONENTS, manifest};

    #[test]
    fn embedded_native_lock_is_complete() {
        let manifest = manifest();
        let mut bundle_ids = HashSet::new();
        for bundle in &manifest.bundles {
            assert!(bundle_ids.insert(&bundle.id), "duplicate bundle id");
            for name in REQUIRED_COMPONENTS {
                let component = bundle
                    .components
                    .iter()
                    .find(|component| component.name == name)
                    .unwrap_or_else(|| panic!("{} is missing {name}", bundle.id));
                assert!(component.size > 0);
                assert_eq!(component.sha256.len(), 64);
                assert!(
                    component
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                );
            }
        }
    }
}
