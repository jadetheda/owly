//! Deterministic KDE Connect device identity and X.509 certificate generation
//! for app-less Apple peers discovered via Owly (AWDL/AirDrop) or BlueZ.
//!
//! Satisfies KDE Connect's strict validation rules in `DeviceInfo`, `Device`,
//! and `LanLinkProvider`:
//! - `deviceId` matches `^[a-zA-Z0-9_-]{32,38}$` (`owly_` + 31 hex chars = 36 chars).
//! - X.509 certificate Subject `CN` equals `deviceId` (`socket->peerCertificate().subjectDisplayName()`).
//! - SubjectAltName includes `deviceId` for `QSslSocket::setPeerVerifyName(deviceId)`.
//! - Validity period starts in the past and expires in the future so `Device::hasInvalidCertificate()` is false.

use std::io;
use std::path::Path;
use std::sync::Arc;

use p256::ecdsa::signature::Signer;
use p256::pkcs8::EncodePrivateKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};

use owly_airdrop::driver::tls::VERSIONS;

/// Derives a valid 36-character KDE Connect `deviceId` (`owly_` + 31 lowercase hex chars)
/// from any stable peer key (such as Bluetooth MAC, AirDrop service instance, or computer name).
pub fn derive_device_id(peer_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"owly-kdeconnect-v1:");
    hasher.update(peer_key.trim().to_ascii_lowercase().as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("owly_{}", &hex[..31])
}

/// Filters a device name the same way `DeviceInfo::filterName` in `kdeconnect-kde` does.
pub fn filter_device_name(name: &str) -> String {
    let filtered: String = name
        .chars()
        .filter(|c| !matches!(c, '"' | '\'' | ',' | ';' | ':' | '.' | '!' | '?' | '(' | ')' | '[' | ']' | '<' | '>'))
        .take(32)
        .collect();
    if filtered.trim().is_empty() {
        "Apple Device".to_string()
    } else {
        filtered
    }
}

/// Maps an Apple model string (e.g. `iPhone16,2`, `iPad14,1`, `MacBookPro18,3`) to KDE Connect's `deviceType`.
pub fn map_apple_model_to_device_type(model: &str) -> &'static str {
    let lower = model.to_ascii_lowercase();
    if lower.contains("ipad") {
        "tablet"
    } else if lower.contains("macbook") {
        "laptop"
    } else if lower.contains("mac") || lower.contains("imac") {
        "desktop"
    } else if lower.contains("appletv") || lower.contains("tv") {
        "tv"
    } else {
        "phone"
    }
}

/// A virtual KDE Connect device's TLS identity (certificate + P-256 private key + PEM representation).
#[derive(Debug)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub cert_der: CertificateDer<'static>,
    pub cert_pem: String,
    key_der: PrivatePkcs8KeyDer<'static>,
}

impl Clone for DeviceIdentity {
    fn clone(&self) -> Self {
        Self {
            device_id: self.device_id.clone(),
            cert_der: self.cert_der.clone(),
            cert_pem: self.cert_pem.clone(),
            key_der: self.key_der.clone_key(),
        }
    }
}

impl DeviceIdentity {
    /// Generates a deterministic or persisted P-256 self-signed X.509 certificate for `device_id`.
    pub fn load_or_generate(state_dir: &Path, device_id: &str) -> io::Result<Self> {
        let peer_dir = state_dir.join("peers").join(device_id);
        let cert_path = peer_dir.join("cert.der");
        let pem_path = peer_dir.join("cert.pem");
        let key_path = peer_dir.join("key.der");

        if let (Ok(cert_bytes), Ok(pem_str), Ok(key_bytes)) = (
            std::fs::read(&cert_path),
            std::fs::read_to_string(&pem_path),
            std::fs::read(&key_path),
        ) {
            return Ok(Self {
                device_id: device_id.to_string(),
                cert_der: CertificateDer::from(cert_bytes),
                cert_pem: pem_str,
                key_der: PrivatePkcs8KeyDer::from(key_bytes),
            });
        }

        let identity = Self::generate(device_id)?;
        std::fs::create_dir_all(&peer_dir)?;
        write_private(&key_path, identity.key_der.secret_pkcs8_der())?;
        std::fs::write(&cert_path, identity.cert_der.as_ref())?;
        std::fs::write(&pem_path, identity.cert_pem.as_bytes())?;
        Ok(identity)
    }

    pub fn generate(device_id: &str) -> io::Result<Self> {
        let key = loop {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
            if let Ok(signing_key) = p256::ecdsa::SigningKey::from_bytes(&bytes.into()) {
                break EcKey::new(signing_key);
            }
        };

        let mut params =
            rcgen::CertificateParams::new(vec![device_id.to_string()]).map_err(io::Error::other)?;
        let mut serial = [0u8; 16];
        getrandom::fill(&mut serial).map_err(|e| io::Error::other(e.to_string()))?;
        serial[0] &= 0x7f;
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));

        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, device_id);
        dn.push(rcgen::DnType::OrganizationName, "KDE");
        dn.push(rcgen::DnType::OrganizationalUnitName, "KDE Connect");
        params.distinguished_name = dn;

        let cert = params.self_signed(&key).map_err(io::Error::other)?;
        let cert_pem = cert.pem();
        let pkcs8 = key.key.to_pkcs8_der().map_err(io::Error::other)?;

        Ok(Self {
            device_id: device_id.to_string(),
            cert_der: cert.der().clone(),
            cert_pem,
            key_der: PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()),
        })
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key_der.clone_key())
    }

    /// TLS ServerConfig for KDE Connect connections where `kdeconnectd` acts as TLS Client
    /// (both the initial `LanLinkProvider::tcpPacketReceived` reverse-TLS handshake and
    /// incoming file downloads where `kdeconnectd` connects to our `payloadTransferInfo.port`).
    pub fn tls_server_config(&self) -> io::Result<Arc<ServerConfig>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let provider = CryptoProvider::get_default()
            .cloned()
            .ok_or_else(|| io::Error::other("no rustls crypto provider installed"))?;
        let verifier = Arc::new(AcceptAnyPeerClient(
            provider.signature_verification_algorithms,
        ));
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(VERSIONS)
            .map_err(io::Error::other)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![self.cert_der.clone()], self.private_key())
            .map_err(io::Error::other)?;
        Ok(Arc::new(config))
    }

    /// TLS ClientConfig presenting this device's client certificate, used when connecting
    /// to `kdeconnectd`'s `CompositeUploadJob` server (`socket->startServerEncryption()`)
    /// or when responding to a UDP discovery broadcast.
    pub fn tls_client_config(&self) -> io::Result<Arc<ClientConfig>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let provider = CryptoProvider::get_default()
            .cloned()
            .ok_or_else(|| io::Error::other("no rustls crypto provider installed"))?;
        let verifier = Arc::new(AcceptAnyPeerServer(
            provider.signature_verification_algorithms,
        ));
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(VERSIONS)
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![self.cert_der.clone()], self.private_key())
            .map_err(io::Error::other)?;
        Ok(Arc::new(config))
    }

    pub fn server_name(&self) -> ServerName<'static> {
        ServerName::try_from(self.device_id.clone())
            .unwrap_or_else(|_| ServerName::try_from("kdeconnect.local").unwrap())
    }
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(data)
}

struct EcKey {
    key: p256::ecdsa::SigningKey,
    public: Vec<u8>,
}

impl EcKey {
    fn new(key: p256::ecdsa::SigningKey) -> Self {
        let public = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self { key, public }
    }
}

impl rcgen::PublicKeyData for EcKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for EcKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: p256::ecdsa::Signature = self.key.sign(msg);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

#[derive(Debug)]
struct AcceptAnyPeerServer(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AcceptAnyPeerServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[derive(Debug)]
struct AcceptAnyPeerClient(WebPkiSupportedAlgorithms);

impl ClientCertVerifier for AcceptAnyPeerClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_matches_kdeconnect_regex() {
        let id = derive_device_id("aa:bb:cc:dd:ee:ff");
        assert_eq!(id.len(), 36);
        assert!(id.starts_with("owly_"));
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }

    #[test]
    fn generates_valid_self_signed_identity() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let id = derive_device_id("iPhone-test");
        let ident = DeviceIdentity::generate(&id).unwrap();
        assert!(ident.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ident.tls_server_config().is_ok());
        assert!(ident.tls_client_config().is_ok());
    }
}
