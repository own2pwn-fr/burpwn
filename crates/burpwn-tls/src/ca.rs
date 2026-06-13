//! Per-install root Certificate Authority for the transparent MITM.
//!
//! The CA is generated once and persisted under the caller-supplied data
//! directory (e.g. `$XDG_DATA_HOME/burpwn`) as two files:
//!
//! - `ca.pem` — the CA certificate, PEM-encoded (exported by `burpwn ca export`
//!   for the user to import into their browser / OS trust store).
//! - `ca.key` — the CA private key (PKCS#8 PEM, ECDSA P-256), written `0600`.
//!
//! On subsequent runs both files are parsed back and reused, so a browser only
//! has to trust the CA once.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::CertificateDer;

use crate::error::{Result, TlsError};

/// File name of the persisted CA certificate (PEM).
const CA_CERT_FILE: &str = "ca.pem";
/// File name of the persisted CA private key (PKCS#8 PEM).
const CA_KEY_FILE: &str = "ca.key";
/// Common name burned into the generated CA certificate.
const CA_COMMON_NAME: &str = "burpwn MITM CA";

/// The per-install root CA: its signing key plus the issuer parameters and the
/// original certificate bytes needed to build a leaf's chain.
///
/// Cloneable so a [`crate::LeafGenerator`] can own a copy without locking.
#[derive(Clone)]
pub struct CertAuthority {
    /// Issuer parameters (distinguished name, key-id method, key usages) used to
    /// sign leaves. Derived from the stored cert so the AuthorityKeyIdentifier on
    /// leaves matches the persisted CA.
    params: CertificateParams,
    /// The CA signing key (ECDSA P-256) as PKCS#8 PEM, so the type stays `Clone`
    /// and reconstruction is a single `KeyPair::from_pem`.
    key_pem: String,
    /// The original CA certificate DER, served as the second link of every leaf
    /// chain.
    cert_der: CertificateDer<'static>,
    /// The CA certificate PEM, cached for `cert_pem()` / `burpwn ca export`.
    cert_pem: String,
}

impl std::fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertAuthority")
            .field("common_name", &CA_COMMON_NAME)
            .finish_non_exhaustive()
    }
}

impl CertAuthority {
    /// Load the CA from `dir`, generating and persisting a fresh one the first
    /// time (both files absent). If one file exists but not the other, that is a
    /// malformed state and the caller gets a [`TlsError`].
    pub fn load_or_generate(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);

        match (cert_path.exists(), key_path.exists()) {
            (true, true) => Self::load(&cert_path, &key_path),
            (false, false) => Self::generate_and_store(dir, &cert_path, &key_path),
            (cert, _) => {
                let missing = if cert { &key_path } else { &cert_path };
                Err(TlsError::MalformedCa {
                    path: missing.clone(),
                    detail: "exactly one of ca.pem / ca.key is present; refusing to guess".into(),
                })
            }
        }
    }

    /// Parse an existing CA from its two files.
    fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = fs::read_to_string(cert_path).map_err(|e| TlsError::io(cert_path, e))?;
        let key_pem = fs::read_to_string(key_path).map_err(|e| TlsError::io(key_path, e))?;

        let key = KeyPair::from_pem(&key_pem).map_err(|e| TlsError::MalformedCa {
            path: key_path.to_path_buf(),
            detail: format!("not a valid PKCS#8 key: {e}"),
        })?;

        let params =
            CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|e| TlsError::MalformedCa {
                path: cert_path.to_path_buf(),
                detail: format!("not a valid CA certificate: {e}"),
            })?;

        let cert_der = pem_to_cert_der(&cert_pem).ok_or_else(|| TlsError::MalformedCa {
            path: cert_path.to_path_buf(),
            detail: "PEM contained no CERTIFICATE block".into(),
        })?;

        Ok(Self {
            params,
            key_pem: key.serialize_pem(),
            cert_der,
            cert_pem,
        })
    }

    /// Generate a brand-new CA, persist it, and return it.
    fn generate_and_store(dir: &Path, cert_path: &Path, key_path: &Path) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|e| TlsError::io(dir, e))?;

        let key = KeyPair::generate()?; // ECDSA P-256 by default
        let params = ca_params()?;
        let cert = params.clone().self_signed(&key)?;

        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        // Write the cert (world-readable is fine — it is public).
        fs::write(cert_path, cert_pem.as_bytes()).map_err(|e| TlsError::io(cert_path, e))?;

        // Write the key, then lock it down to 0600.
        fs::write(key_path, key_pem.as_bytes()).map_err(|e| TlsError::io(key_path, e))?;
        let mut perms = fs::metadata(key_path)
            .map_err(|e| TlsError::io(key_path, e))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(key_path, perms).map_err(|e| TlsError::io(key_path, e))?;

        Ok(Self {
            params,
            key_pem: key.serialize_pem(),
            cert_der: cert.der().clone(),
            cert_pem,
        })
    }

    /// The CA certificate as PEM, for `burpwn ca export`.
    pub fn cert_pem(&self) -> String {
        self.cert_pem.clone()
    }

    /// The CA certificate DER (the trust-anchor link appended to every leaf
    /// chain).
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// Reconstruct the signing key. Cheap-ish (a parse), done once per minted
    /// leaf; leaves are cached so this is not on the hot path.
    pub(crate) fn signing_key(&self) -> Result<KeyPair> {
        KeyPair::from_pem(&self.key_pem).map_err(TlsError::from)
    }

    /// Rebuild the issuer certificate used by rcgen's `signed_by`. Its
    /// distinguished name and subject-key-identifier match the persisted CA, so
    /// leaves chain to [`Self::cert_der`].
    pub(crate) fn issuer_cert(&self, key: &KeyPair) -> Result<Certificate> {
        self.params.clone().self_signed(key).map_err(TlsError::from)
    }
}

/// Build the `CertificateParams` for a fresh root CA: ECDSA P-256, CA with
/// path-len 0, keyCertSign + cRLSign, ~10-year validity.
fn ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, "burpwn");
    params.distinguished_name = dn;

    // A leaf-issuing root: it may sign end-entities but not sub-CAs.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // ~10 years of validity, anchored to a real civil timestamp. `not_before`
    // sits a couple of days in the past so the CA is never "not yet valid"
    // under clock skew or the old year approximation.
    let validity = crate::Validity::for_years(10);
    params.not_before = validity.not_before;
    params.not_after = validity.not_after;

    Ok(params)
}

/// Extract the first CERTIFICATE block of a PEM string as owned DER.
fn pem_to_cert_der(pem: &str) -> Option<CertificateDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let first = rustls_pemfile::certs(&mut cursor).next();
    first.and_then(|r| r.ok())
}

/// Default per-user data directory for the CA, following the XDG spec
/// (`$XDG_DATA_HOME/burpwn` or `~/.local/share/burpwn`). The binary may pass its
/// own path instead.
pub fn default_data_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("fr", "own2pwn", "burpwn").map(|d| d.data_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_then_load_round_trips() {
        let dir = TempDir::new().unwrap();
        let ca1 = CertAuthority::load_or_generate(dir.path()).unwrap();
        let pem1 = ca1.cert_pem();
        assert!(pem1.contains("BEGIN CERTIFICATE"));
        assert!(pem1.contains("END CERTIFICATE"));

        // Files are present.
        assert!(dir.path().join(CA_CERT_FILE).exists());
        assert!(dir.path().join(CA_KEY_FILE).exists());

        // Second call loads (does not regenerate): same cert bytes.
        let ca2 = CertAuthority::load_or_generate(dir.path()).unwrap();
        assert_eq!(ca1.cert_der(), ca2.cert_der());
        assert_eq!(pem1, ca2.cert_pem());
    }

    #[test]
    fn key_file_is_0600() {
        let dir = TempDir::new().unwrap();
        let _ = CertAuthority::load_or_generate(dir.path()).unwrap();
        let mode = fs::metadata(dir.path().join(CA_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "key must be owner-only");
    }

    #[test]
    fn cert_pem_is_parseable_der() {
        let dir = TempDir::new().unwrap();
        let ca = CertAuthority::load_or_generate(dir.path()).unwrap();
        let der = pem_to_cert_der(&ca.cert_pem()).expect("pem parses to a cert");
        assert_eq!(&der, ca.cert_der());
    }

    #[test]
    fn signing_key_and_issuer_reconstruct() {
        let dir = TempDir::new().unwrap();
        let ca = CertAuthority::load_or_generate(dir.path()).unwrap();
        let key = ca.signing_key().unwrap();
        // Rebuilding the issuer cert must succeed (DN/key-id derived from store).
        let _issuer = ca.issuer_cert(&key).unwrap();
    }

    #[test]
    fn fresh_ca_not_before_is_in_the_past() {
        use x509_parser::prelude::*;
        let dir = TempDir::new().unwrap();
        let ca = CertAuthority::load_or_generate(dir.path()).unwrap();
        let (_, cert) = X509Certificate::from_der(ca.cert_der().as_ref()).unwrap();

        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        assert!(
            not_before <= now,
            "CA not_before {not_before} must be <= now {now}"
        );
        assert!(
            not_after > now,
            "CA not_after {not_after} must be in the future"
        );
    }

    #[test]
    fn half_present_state_is_rejected() {
        let dir = TempDir::new().unwrap();
        // Only the key, no cert.
        fs::write(dir.path().join(CA_KEY_FILE), b"junk").unwrap();
        let err = CertAuthority::load_or_generate(dir.path()).unwrap_err();
        assert!(matches!(err, TlsError::MalformedCa { .. }));
    }
}
