//! On-the-fly leaf-certificate generation, keyed and cached by SNI (or by
//! destination IP when SNI is absent).
//!
//! Every intercepted connection needs a server certificate the client will
//! accept *as if* it were the real site's: same name in the SAN, signed by our
//! CA (which the user has trusted once). Minting is comparatively expensive
//! (keygen + signature), so results are cached in a [`DashMap`] keyed by the SNI
//! / IP string; concurrent requests for the same key mint exactly once via the
//! entry API.

use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, Ia5String, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::sign::CertifiedKey;

use crate::ca::CertAuthority;
use crate::error::{Result, TlsError};

/// Mints and caches leaf certificates signed by the install CA.
#[derive(Debug)]
pub struct LeafGenerator {
    ca: CertAuthority,
    cache: DashMap<String, Arc<CertifiedKey>>,
}

impl LeafGenerator {
    /// Build a generator over a loaded CA.
    pub fn new(ca: CertAuthority) -> Self {
        Self {
            ca,
            cache: DashMap::new(),
        }
    }

    /// The underlying CA (e.g. for `cert_pem` export).
    pub fn ca(&self) -> &CertAuthority {
        &self.ca
    }

    /// Number of cached leaves (diagnostics / tests).
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Get a leaf for `(sni, dst_ip)`, minting and caching it on first use.
    ///
    /// The cache key is the SNI when present, otherwise the destination IP. At
    /// least one of the two must be supplied; with neither there is nothing to
    /// put in the certificate, so this returns [`TlsError::InvalidSan`].
    ///
    /// Concurrency: two callers racing on the same key both go through the
    /// `entry` API, so the leaf is minted exactly once and the loser gets the
    /// winner's `Arc`.
    pub fn get_or_make(
        &self,
        sni: Option<&str>,
        dst_ip: Option<IpAddr>,
    ) -> Result<Arc<CertifiedKey>> {
        let key = cache_key(sni, dst_ip)?;

        // Fast path: already cached.
        if let Some(existing) = self.cache.get(&key) {
            return Ok(existing.value().clone());
        }

        // Slow path: mint, then insert via the entry API so concurrent callers
        // for the same key dedupe — if another task won the race, we drop our
        // freshly minted key and return theirs.
        let minted = Arc::new(self.mint(sni, dst_ip)?);
        let entry = self.cache.entry(key).or_insert(minted);
        Ok(entry.value().clone())
    }

    /// Build (without caching) a `CertifiedKey` for the given SAN inputs.
    fn mint(&self, sni: Option<&str>, dst_ip: Option<IpAddr>) -> Result<CertifiedKey> {
        let leaf_key = KeyPair::generate()?; // ECDSA P-256
        let params = leaf_params(sni, dst_ip)?;

        let ca_key = self.ca.signing_key()?;
        let issuer = self.ca.issuer_cert(&ca_key)?;
        let leaf_cert = params.signed_by(&leaf_key, &issuer, &ca_key)?;

        // Chain = [leaf, CA]. The CA is the original persisted DER so the chain
        // verifies against the anchor the user imported.
        let chain = vec![leaf_cert.der().clone(), self.ca.cert_der().clone()];

        // rustls signing key from the leaf's PKCS#8 DER.
        let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let signing_key = any_ecdsa_type(&key_der.into())?;

        Ok(CertifiedKey::new(chain, signing_key))
    }
}

/// Compute the cache key for `(sni, dst_ip)`.
fn cache_key(sni: Option<&str>, dst_ip: Option<IpAddr>) -> Result<String> {
    match (sni, dst_ip) {
        (Some(s), _) if !s.is_empty() => Ok(s.to_ascii_lowercase()),
        (_, Some(ip)) => Ok(ip.to_string()),
        _ => Err(TlsError::InvalidSan(
            String::new(),
            "neither SNI nor destination IP supplied".into(),
        )),
    }
}

/// Build leaf `CertificateParams`: the SNI as a DNS SAN and/or the dst IP as an
/// IP SAN, server-auth EKU, short validity.
fn leaf_params(sni: Option<&str>, dst_ip: Option<IpAddr>) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;

    let mut sans = Vec::new();
    let mut cn = None;
    if let Some(s) = sni.filter(|s| !s.is_empty()) {
        let dns = Ia5String::try_from(s.to_string())
            .map_err(|e| TlsError::InvalidSan(s.to_string(), e.to_string()))?;
        sans.push(SanType::DnsName(dns));
        cn = Some(s.to_string());
    }
    if let Some(ip) = dst_ip {
        sans.push(SanType::IpAddress(ip));
        cn.get_or_insert_with(|| ip.to_string());
    }
    if sans.is_empty() {
        return Err(TlsError::InvalidSan(
            String::new(),
            "no SNI or IP to place in the leaf".into(),
        ));
    }
    params.subject_alt_names = sans;

    if let Some(cn) = cn {
        params.distinguished_name.push(DnType::CommonName, cn);
    }

    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    // Short-ish validity: minted on demand, regenerated freely. Spans the
    // current year through next year-end (~1-2 years).
    let year = crate::current_year();
    params.not_before = rcgen::date_time_ymd(year, 1, 1);
    params.not_after = rcgen::date_time_ymd(year + 2, 1, 1);

    Ok(params)
}

/// Validate that `name` is usable as a TLS server name (defensive helper the
/// proxy can call on a captured SNI before handing it here).
pub fn is_valid_server_name(name: &str) -> bool {
    ServerName::try_from(name.to_string()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertAuthority;
    use std::net::Ipv4Addr;
    use tempfile::TempDir;

    fn generator() -> (TempDir, LeafGenerator) {
        let dir = TempDir::new().unwrap();
        let ca = CertAuthority::load_or_generate(dir.path()).unwrap();
        (dir, LeafGenerator::new(ca))
    }

    /// Parse the leaf DER and assert its SAN list / chain via x509-parser
    /// (pulled in transitively through rcgen's `x509-parser` feature).
    fn leaf_dns_sans(ck: &CertifiedKey) -> Vec<String> {
        use x509_parser::prelude::*;
        let der = &ck.cert[0];
        let (_, cert) = X509Certificate::from_der(der.as_ref()).unwrap();
        let mut out = Vec::new();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for gn in &san.value.general_names {
                if let GeneralName::DNSName(d) = gn {
                    out.push(d.to_string());
                }
            }
        }
        out
    }

    fn leaf_ip_sans(ck: &CertifiedKey) -> Vec<IpAddr> {
        use x509_parser::prelude::*;
        let der = &ck.cert[0];
        let (_, cert) = X509Certificate::from_der(der.as_ref()).unwrap();
        let mut out = Vec::new();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for gn in &san.value.general_names {
                if let GeneralName::IPAddress(bytes) = gn {
                    match bytes.len() {
                        4 => {
                            let a: [u8; 4] = (*bytes).try_into().unwrap();
                            out.push(IpAddr::from(a));
                        }
                        16 => {
                            let a: [u8; 16] = (*bytes).try_into().unwrap();
                            out.push(IpAddr::from(a));
                        }
                        _ => {}
                    }
                }
            }
        }
        out
    }

    #[test]
    fn leaf_has_dns_san_and_chains_to_ca() {
        let (_d, gen) = generator();
        let ck = gen.get_or_make(Some("example.com"), None).unwrap();
        assert_eq!(ck.cert.len(), 2, "chain = [leaf, ca]");
        assert_eq!(leaf_dns_sans(&ck), vec!["example.com".to_string()]);
        // Second cert in the chain is the CA.
        assert_eq!(&ck.cert[1], gen.ca().cert_der());
    }

    #[test]
    fn same_sni_returns_cached_arc() {
        let (_d, gen) = generator();
        let a = gen.get_or_make(Some("example.com"), None).unwrap();
        let b = gen.get_or_make(Some("EXAMPLE.com"), None).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "case-insensitive cache hit, same Arc");
        assert_eq!(gen.cache_len(), 1);
    }

    #[test]
    fn ip_only_yields_ip_san() {
        let (_d, gen) = generator();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ck = gen.get_or_make(None, Some(ip)).unwrap();
        assert_eq!(leaf_ip_sans(&ck), vec![ip]);
        assert!(leaf_dns_sans(&ck).is_empty());
    }

    #[test]
    fn neither_sni_nor_ip_is_error() {
        let (_d, gen) = generator();
        assert!(gen.get_or_make(None, None).is_err());
        assert!(gen.get_or_make(Some(""), None).is_err());
    }

    #[test]
    fn distinct_keys_cache_separately() {
        let (_d, gen) = generator();
        let _ = gen.get_or_make(Some("a.example"), None).unwrap();
        let _ = gen.get_or_make(Some("b.example"), None).unwrap();
        assert_eq!(gen.cache_len(), 2);
    }
}
