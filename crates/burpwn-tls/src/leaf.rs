//! On-the-fly leaf-certificate generation, keyed and cached by SNI (or by
//! destination IP when SNI is absent).
//!
//! Every intercepted connection needs a server certificate the client will
//! accept *as if* it were the real site's: same name in the SAN, signed by our
//! CA (which the user has trusted once). Minting is comparatively expensive
//! (keygen + signature), so results are cached keyed by the SNI / IP string.
//!
//! The cache is a **bounded** LRU ([`lru::LruCache`] behind a
//! [`parking_lot::Mutex`]). The key is client-supplied (SNI or destination IP),
//! so an unbounded map would let an attacker opening TLS with endless distinct
//! SNIs grow memory and burn ECDSA keygen without limit. Capping at
//! [`CACHE_CAP`] entries evicts the least-recently-used leaf instead.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use parking_lot::Mutex;
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, Ia5String, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::sign::CertifiedKey;

use crate::ca::CertAuthority;
use crate::error::{Result, TlsError};

/// Maximum number of distinct leaf certificates kept in the cache. Once full,
/// inserting a new key evicts the least-recently-used one. Bounds attacker-driven
/// memory + keygen cost from many distinct client-supplied SNIs.
const CACHE_CAP: usize = 2048;

/// Mints and caches leaf certificates signed by the install CA.
#[derive(Debug)]
pub struct LeafGenerator {
    ca: CertAuthority,
    /// Bounded LRU keyed by SNI (lowercased) or destination IP. Guarded by a
    /// `parking_lot::Mutex` — lookups are short (hash + `Arc` clone) so the
    /// critical section is tiny.
    cache: Mutex<LruCache<String, Arc<CertifiedKey>>>,
}

impl LeafGenerator {
    /// Build a generator over a loaded CA.
    pub fn new(ca: CertAuthority) -> Self {
        // CACHE_CAP is a non-zero constant; the unwrap can never fire.
        let cap = NonZeroUsize::new(CACHE_CAP).expect("CACHE_CAP must be non-zero");
        Self {
            ca,
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

    /// The underlying CA (e.g. for `cert_pem` export).
    pub fn ca(&self) -> &CertAuthority {
        &self.ca
    }

    /// Number of cached leaves (diagnostics / tests). Always `<= CACHE_CAP`.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().len()
    }

    /// The cache capacity (upper bound on [`Self::cache_len`]).
    pub fn cache_cap(&self) -> usize {
        CACHE_CAP
    }

    /// Get a leaf for `(sni, dst_ip)`, minting and caching it on first use.
    ///
    /// The cache key is the SNI when present, otherwise the destination IP. At
    /// least one of the two must be supplied; with neither there is nothing to
    /// put in the certificate, so this returns [`TlsError::InvalidSan`].
    ///
    /// Concurrency: the lock is held only for the (cheap) cache lookup and
    /// insert, never across minting — so concurrent callers for *different* keys
    /// mint in parallel. Two callers racing on the *same* key may both mint
    /// (a benign double-mint, never a panic); the second insert collapses them
    /// back to one cached `Arc` and the first minted key is dropped. The cache
    /// is bounded at [`CACHE_CAP`]; a full cache evicts the LRU entry.
    pub fn get_or_make(
        &self,
        sni: Option<&str>,
        dst_ip: Option<IpAddr>,
    ) -> Result<Arc<CertifiedKey>> {
        let key = cache_key(sni, dst_ip)?;

        // Fast path: already cached (and marks the entry most-recently-used).
        if let Some(existing) = self.cache.lock().get(&key) {
            return Ok(existing.clone());
        }

        // Slow path: mint *without* holding the lock (keygen + signature are
        // expensive), then insert. If another task inserted the same key while
        // we were minting, return the already-cached one and drop ours.
        let minted = Arc::new(self.mint(sni, dst_ip)?);
        let mut cache = self.cache.lock();
        if let Some(existing) = cache.get(&key) {
            return Ok(existing.clone());
        }
        cache.put(key, minted.clone());
        Ok(minted)
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

    // Validity anchored to a real civil timestamp: `not_before` is a couple of
    // days in the past (clock-skew tolerant, never "not yet valid"), `not_after`
    // ~2 years out. Leaves are minted on demand and regenerated freely.
    let validity = crate::Validity::for_years(2);
    params.not_before = validity.not_before;
    params.not_after = validity.not_after;

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

    /// Inserting more than the cache cap of distinct keys must keep the cache
    /// bounded (never grows without limit) while still returning valid certs.
    #[test]
    fn cache_is_bounded_under_many_keys() {
        let (_d, gen) = generator();
        let cap = gen.cache_cap();
        // Mint cap + a healthy overflow of distinct SNIs.
        for i in 0..(cap + 100) {
            let sni = format!("host-{i}.example");
            let ck = gen.get_or_make(Some(&sni), None).unwrap();
            // Each minted leaf is well-formed: chain = [leaf, ca] and carries
            // its own SNI as a DNS SAN.
            assert_eq!(ck.cert.len(), 2);
            assert_eq!(leaf_dns_sans(&ck), vec![sni]);
        }
        assert!(
            gen.cache_len() <= cap,
            "cache must stay bounded: len {} > cap {cap}",
            gen.cache_len()
        );
        assert_eq!(gen.cache_len(), cap, "cache should be saturated at the cap");
    }

    /// A freshly minted leaf's `not_before` must be at or before "now": never
    /// in the future, or every client rejects the handshake as not-yet-valid.
    #[test]
    fn fresh_leaf_not_before_is_in_the_past() {
        use x509_parser::prelude::*;
        let (_d, gen) = generator();
        let ck = gen.get_or_make(Some("example.com"), None).unwrap();
        let (_, cert) = X509Certificate::from_der(ck.cert[0].as_ref()).unwrap();

        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        assert!(
            not_before <= now,
            "not_before {not_before} must be <= now {now}"
        );
        assert!(
            not_after > now,
            "not_after {not_after} must be in the future"
        );
    }
}
