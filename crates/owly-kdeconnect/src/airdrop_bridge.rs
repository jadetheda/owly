//! Owly AirDrop + AWDL (`owlyd`) + BLE Wake Advertisement bridge for KDE Connect.
//!
//! Connects `owly-airdrop` (`Receiver`, `Sender`, `Mdns`) and `owlyd`
//! (`io.github.t4t5.Owly.Radio1`) to KDE Connect's device and plugin endpoints.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use owly_airdrop::driver::mdns::Mdns;
use owly_airdrop::driver::receiver::{Options, Receiver, ReceiverEvent, Request};
use owly_airdrop::driver::sender::{Event as SenderEvent, Payload, Sender};
use owly_airdrop::driver::tls::Identity as AirdropIdentity;
use owly_airdrop::proto::ble::{APPLE_COMPANY_ID, Advert, INTERVAL_MS};
use owly_airdrop::proto::mdns::{self, BrowseEvent, RECEIVER_FLAGS, SUPPORTS_DVZIP, Service};
use owly_airdrop::proto::messages::Offer;
use owly_airdrop::proto::receiver::Config as ReceiverConfig;
use owly_airdrop::proto::sender::{self, Outcome};
use owly_awdl::MacAddr;
use owlyd::api::{self, LinkInfo};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast, mpsc};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value as ZValue};

use crate::identity::{derive_device_id, filter_device_name, map_apple_model_to_device_type};

pub const AIRDROP_PORT: u16 = 8770;
pub const DEFAULT_RECEIVE_PORT: u16 = 8771;
pub const DEFAULT_RECEIVER_FLAGS: u32 = RECEIVER_FLAGS | SUPPORTS_DVZIP;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplePeer {
    pub device_id: String,
    pub instance: String,
    pub name: String,
    pub model: String,
    pub device_type: String,
    pub mac: Option<String>,
    pub addr: Option<SocketAddrV6>,
    pub flags: u32,
    pub rssi: Option<i16>,
    pub paired: bool,
}

impl ApplePeer {
    pub fn from_discovered(
        instance: String,
        name: String,
        model: Option<String>,
        addr: SocketAddrV6,
        flags: u32,
        mac: Option<String>,
    ) -> Self {
        let key = mac.as_deref().unwrap_or(&instance);
        let device_id = derive_device_id(key);
        let filtered_name = filter_device_name(&name);
        let model_str = model.unwrap_or_else(|| "iPhone".to_string());
        let device_type = map_apple_model_to_device_type(&model_str).to_string();
        Self {
            device_id,
            instance,
            name: filtered_name,
            model: model_str,
            device_type,
            mac,
            addr: Some(addr),
            flags,
            rssi: None,
            paired: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum BridgeEvent {
    PeerUpdated(ApplePeer),
    PeerRemoved(String),
    IncomingAsk {
        id: u64,
        peer: ApplePeer,
        sender_name: String,
        sender_model: String,
        summary: String,
        items: Vec<String>,
        is_url: bool,
    },
    AskWithdrawn {
        id: u64,
        peer_device_id: String,
    },
    FilesReceived {
        id: u64,
        peer: ApplePeer,
        paths: Vec<PathBuf>,
    },
    UrlsReceived {
        id: u64,
        peer: ApplePeer,
        urls: Vec<String>,
    },
    TransferProgress {
        peer_device_id: String,
        sent: u64,
        total: u64,
    },
    TransferFailed {
        id: u64,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub iface: String,
    pub computer_name: String,
    pub receive_dir: PathBuf,
    pub state_dir: PathBuf,
    pub receive_port: u16,
    pub auto_accept: bool,
    pub auto_acquire_radio: bool,
    pub bus_address: Option<String>,
    pub no_ble: bool,
    pub no_mdns: bool,
}

impl BridgeConfig {
    pub fn default_with_dirs() -> io::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let state_dir = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state"))
            .join("owly-kdeconnect");
        let receive_dir = std::env::var_os("XDG_DOWNLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("Downloads"));
        let computer_name = nix::unistd::gethostname()
            .ok()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|| "KDE-Linux".to_string());

        Ok(Self {
            iface: "awdl0".to_string(),
            computer_name,
            receive_dir,
            state_dir,
            receive_port: DEFAULT_RECEIVE_PORT,
            auto_accept: false,
            auto_acquire_radio: true,
            bus_address: None,
            no_ble: false,
            no_mdns: false,
        })
    }
}

struct PendingAsk {
    peer: ApplePeer,
    request: Request,
}

#[derive(Debug, Clone)]
pub struct AwdlInterface {
    pub name: String,
    pub index: u32,
    pub addr: Ipv6Addr,
}

impl AwdlInterface {
    pub fn lookup(name: &str) -> io::Result<Self> {
        let index = nix::net::if_::if_nametoindex(name)
            .map_err(|e| io::Error::other(format!("{name}: {e}")))?;
        let addr = nix::ifaddrs::getifaddrs()?
            .filter(|a| a.interface_name == name)
            .filter_map(|a| a.address?.as_sockaddr_in6().map(|s| s.ip()))
            .find(|ip| ip.segments()[0] & 0xffc0 == 0xfe80)
            .ok_or_else(|| io::Error::other(format!("{name} has no IPv6 link-local address")))?;
        Ok(Self {
            name: name.to_string(),
            index,
            addr,
        })
    }
}

pub struct OwlyAirdropBridge {
    config: BridgeConfig,
    peers: Arc<Mutex<HashMap<String, ApplePeer>>>,
    pending_asks: Arc<Mutex<HashMap<u64, PendingAsk>>>,
    ask_peers_by_id: Arc<Mutex<HashMap<u64, ApplePeer>>>,
    events_tx: broadcast::Sender<BridgeEvent>,
    held_lease: Arc<Mutex<Option<(zbus::Connection, u64, LinkInfo)>>>,
}

impl OwlyAirdropBridge {
    pub fn new(config: BridgeConfig) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (events_tx, _) = broadcast::channel(256);
        Self {
            config,
            peers: Arc::new(Mutex::new(HashMap::new())),
            pending_asks: Arc::new(Mutex::new(HashMap::new())),
            ask_peers_by_id: Arc::new(Mutex::new(HashMap::new())),
            events_tx,
            held_lease: Arc::new(Mutex::new(None)),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BridgeEvent> {
        self.events_tx.subscribe()
    }

    pub fn config(&self) -> &BridgeConfig {
        &self.config
    }

    pub async fn list_peers(&self) -> Vec<ApplePeer> {
        self.peers.lock().await.values().cloned().collect()
    }

    pub async fn get_peer(&self, peer_query: &str) -> Option<ApplePeer> {
        let peers = self.peers.lock().await;
        if let Some(p) = peers.get(peer_query) {
            return Some(p.clone());
        }
        peers
            .values()
            .find(|p| {
                p.name.eq_ignore_ascii_case(peer_query)
                    || p.instance.eq_ignore_ascii_case(peer_query)
                    || p.mac
                        .as_deref()
                        .is_some_and(|m| m.eq_ignore_ascii_case(peer_query))
            })
            .cloned()
    }

    pub async fn upsert_peer(&self, peer: ApplePeer) {
        let mut peers = self.peers.lock().await;
        peers.insert(peer.device_id.clone(), peer.clone());
        drop(peers);
        let _ = self.events_tx.send(BridgeEvent::PeerUpdated(peer));
    }

    /// Checks `owlyd`'s `Probe()` JSON to see whether the Wi-Fi card runs in `shared` mode
    /// (keeps normal Wi-Fi connected while `awdl0` is up) or `exclusive` mode (temporarily
    /// borrows the Wi-Fi card for the duration of the AirDrop window).
    pub async fn is_shared_radio_mode(&self) -> bool {
        let Ok(conn) = api::connect(self.config.bus_address.as_deref()).await else {
            return false;
        };
        let Ok(radio) = api::radio(&conn).await else {
            return false;
        };
        let Ok(probe_json) = radio.probe().await else {
            return false;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&probe_json) else {
            return false;
        };
        val.get("mode").and_then(|m| m.as_str()) == Some("shared")
    }

    /// Releases any `owlyd` lease currently held by this bridge so NetworkManager immediately
    /// reconnects normal Wi-Fi on `exclusive`-mode cards.
    pub async fn release_held_lease(&self) {
        let taken = self.held_lease.lock().await.take();
        if let Some((conn, lease_id, _)) = taken
            && let Ok(radio) = api::radio(&conn).await
        {
            let _ = radio.release(lease_id).await;
        }
    }

    /// Ensures the AWDL interface (`awdl0`) is available, acquiring an `owlyd` lease
    /// if `auto_acquire_radio` is enabled and the interface is not already up.
    pub async fn ensure_interface(&self, duration_secs: u32) -> io::Result<(AwdlInterface, Option<LinkInfo>)> {
        if let Ok(iface) = AwdlInterface::lookup(&self.config.iface) {
            let link_info = self.query_owlyd_link().await.ok();
            return Ok((iface, link_info));
        }

        if !self.config.auto_acquire_radio {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {} is not up and auto_acquire_radio is disabled", self.config.iface),
            ));
        }

        let conn = api::connect(self.config.bus_address.as_deref())
            .await
            .map_err(|e| io::Error::other(format!("cannot connect to owlyd bus: {e}")))?;
        let radio = api::radio(&conn)
            .await
            .map_err(|e| io::Error::other(format!("cannot build owlyd proxy: {e}")))?;

        let (lease_id, dict) = radio
            .acquire(duration_secs)
            .await
            .map_err(|e| io::Error::other(format!("owlyd Acquire failed: {e}")))?;
        let link = LinkInfo::from_dict(&dict)
            .ok_or_else(|| io::Error::other("owlyd returned malformed LinkInfo dictionary"))?;

        let iface = AwdlInterface::lookup(&link.interface)?;
        *self.held_lease.lock().await = Some((conn, lease_id, link.clone()));
        Ok((iface, Some(link)))
    }

    async fn query_owlyd_link(&self) -> Result<LinkInfo, String> {
        let conn = api::connect(self.config.bus_address.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        let radio = api::radio(&conn).await.map_err(|e| e.to_string())?;
        let dict = radio.link().await.map_err(|e| e.to_string())?;
        LinkInfo::from_dict(&dict).ok_or_else(|| "owlyd link is not up".to_string())
    }

    async fn query_owlyd_peers(&self) -> Vec<(MacAddr, Option<i16>)> {
        let Ok(conn) = api::connect(self.config.bus_address.as_deref()).await else {
            return Vec::new();
        };
        let Ok(radio) = api::radio(&conn).await else {
            return Vec::new();
        };
        let Ok(peers) = radio.peers().await else {
            return Vec::new();
        };
        peers
            .iter()
            .filter_map(|p| {
                let mac: MacAddr = p.get("mac")?.downcast_ref::<String>().ok()?.parse().ok()?;
                let rssi = p.get("rssi").and_then(|v| v.downcast_ref::<i16>().ok());
                Some((mac, rssi))
            })
            .collect()
    }

    /// Starts the `owly-airdrop` `Receiver` and mDNS responder for `lease_duration_secs`
    /// (`0` = continuous on `shared`-mode cards, or e.g. `90` seconds when woken by an iPhone's
    /// BLE `0x004c` type `0x05` AirDrop advertisement on `exclusive`-mode cards).
    pub async fn start_receiver_window(self: Arc<Self>, lease_duration_secs: u32) -> io::Result<()> {
        std::fs::create_dir_all(&self.config.receive_dir)?;
        std::fs::create_dir_all(&self.config.state_dir)?;

        let (iface, link_info) = self.ensure_interface(lease_duration_secs).await?;
        let identity = AirdropIdentity::load_or_generate(&self.config.state_dir)?;

        let mut rx_config = ReceiverConfig::new(self.config.computer_name.clone());
        rx_config.model_name = "KDE-Connect-Owly".into();

        let bind_addr = SocketAddrV6::new(iface.addr, self.config.receive_port, 0, iface.index);
        let (receiver, mut rx_events) = Receiver::bind(
            bind_addr,
            &identity,
            Options::new(rx_config, self.config.receive_dir.clone()),
        )
        .await?;
        tokio::spawn(receiver.run());

        let service_id = random_service_id()?;
        let burst = link_info.and_then(|l| l.announce).map(|a| mdns::Burst {
            count: a.count,
            interval: a.interval,
            pause: a.pause,
        });

        let _mdns_reg = if self.config.no_mdns {
            None
        } else {
            let service = Service {
                instance: service_id.clone(),
                host: format!("owly-kdeconnect-{service_id}"),
                port: self.config.receive_port,
                addr: iface.addr,
                flags: DEFAULT_RECEIVER_FLAGS,
            };
            Some(
                Mdns::new(iface.index)
                    .with_burst(burst)
                    .register(service)
                    .await?,
            )
        };

        tracing::info!(
            iface = %iface.name,
            addr = %bind_addr,
            name = %self.config.computer_name,
            "Owly AirDrop receiver listening for KDE Connect"
        );

        while let Some(event) = rx_events.recv().await {
            match event {
                ReceiverEvent::Discovered { peer, .. } => {
                    tracing::debug!(peer = %peer, "Apple peer probed our AirDrop /Discover endpoint");
                }
                ReceiverEvent::Request(request) => {
                    let id = request.id;
                    let sender_name = if request.ask.sender_computer_name.is_empty() {
                        "Apple Device".to_string()
                    } else {
                        request.ask.sender_computer_name.clone()
                    };
                    let sender_model = if request.ask.sender_model_name.is_empty() {
                        "iPhone".to_string()
                    } else {
                        request.ask.sender_model_name.clone()
                    };
                    let instance_key = if request.ask.sender_id.is_empty() {
                        request.peer.ip().to_string()
                    } else {
                        request.ask.sender_id.clone()
                    };
                    let peer_addr = SocketAddrV6::new(
                        *request.peer.ip(),
                        AIRDROP_PORT,
                        0,
                        iface.index,
                    );
                    let apple_peer = ApplePeer::from_discovered(
                        instance_key,
                        sender_name.clone(),
                        Some(sender_model.clone()),
                        peer_addr,
                        DEFAULT_RECEIVER_FLAGS,
                        None,
                    );
                    self.upsert_peer(apple_peer.clone()).await;
                    self.ask_peers_by_id
                        .lock()
                        .await
                        .insert(id, apple_peer.clone());

                    let (summary, items, is_url) = match &request.ask.offer {
                        Offer::Files(files) => {
                            let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
                            let desc = if names.len() == 1 {
                                format!("Wants to send file: {}", names[0])
                            } else {
                                format!("Wants to send {} files: {}", names.len(), names.join(", "))
                            };
                            (desc, names, false)
                        }
                        Offer::Urls(urls) => {
                            let desc = format!("Wants to share link: {}", urls.join(", "));
                            (desc, urls.clone(), true)
                        }
                    };

                    if self.config.auto_accept {
                        request.accept();
                    } else {
                        self.pending_asks.lock().await.insert(
                            id,
                            PendingAsk {
                                peer: apple_peer.clone(),
                                request,
                            },
                        );
                        let _ = self.events_tx.send(BridgeEvent::IncomingAsk {
                            id,
                            peer: apple_peer,
                            sender_name,
                            sender_model,
                            summary,
                            items,
                            is_url,
                        });
                    }
                }
                ReceiverEvent::Withdrawn { id } => {
                    let removed = self.pending_asks.lock().await.remove(&id);
                    let peer_id = removed
                        .map(|p| p.peer.device_id)
                        .or_else(|| {
                            None
                        })
                        .unwrap_or_default();
                    let _ = self.events_tx.send(BridgeEvent::AskWithdrawn {
                        id,
                        peer_device_id: peer_id,
                    });
                }
                ReceiverEvent::Received { id, paths } => {
                    let peer = self
                        .ask_peers_by_id
                        .lock()
                        .await
                        .remove(&id)
                        .unwrap_or_else(|| {
                            ApplePeer::from_discovered(
                                "airdrop-peer".into(),
                                "Apple Device".into(),
                                Some("iPhone".into()),
                                bind_addr,
                                DEFAULT_RECEIVER_FLAGS,
                                None,
                            )
                        });
                    let _ = self
                        .events_tx
                        .send(BridgeEvent::FilesReceived { id, peer, paths });
                }
                ReceiverEvent::Urls { id, urls } => {
                    let peer = self
                        .ask_peers_by_id
                        .lock()
                        .await
                        .remove(&id)
                        .unwrap_or_else(|| {
                            ApplePeer::from_discovered(
                                "airdrop-peer".into(),
                                "Apple Device".into(),
                                Some("iPhone".into()),
                                bind_addr,
                                DEFAULT_RECEIVER_FLAGS,
                                None,
                            )
                        });
                    let _ = self
                        .events_tx
                        .send(BridgeEvent::UrlsReceived { id, peer, urls });
                }
                ReceiverEvent::Failed { id, reason } => {
                    let _ = self
                        .events_tx
                        .send(BridgeEvent::TransferFailed { id, reason });
                }
            }
        }

        Ok(())
    }

    /// Accepts or declines a pending `/Ask` prompt (triggered from a KDE Connect notification button or D-Bus).
    pub async fn answer_ask(&self, transfer_id: u64, accept: bool) -> bool {
        let Some(pending) = self.pending_asks.lock().await.remove(&transfer_id) else {
            return false;
        };
        if accept {
            pending.request.accept();
        } else {
            pending.request.decline();
        }
        true
    }

    /// Actively wakes nearby Apple devices over BLE, browses mDNS (`_airdrop._tcp.local.`),
    /// and knocks AWDL peers on port 8770 (`/Discover`) to populate the KDE Connect device list.
    pub async fn discover_peers(&self, timeout_secs: u64) -> io::Result<Vec<ApplePeer>> {
        let (iface, _) = self.ensure_interface(timeout_secs as u32 + 30).await?;
        let _ble_guard = advertise_ble(self.config.no_ble).await;
        let sender = Sender::new(sender::Config::new(
            self.config.computer_name.clone(),
            random_service_id()?,
        ))?;

        let limit = Duration::from_secs(timeout_secs.max(3));
        let deadline = tokio::time::Instant::now() + limit;

        // 1. Try AWDL peers reported by owlyd alongside mDNS
        let awdl_peers = self.query_owlyd_peers().await;
        for (mac, rssi) in awdl_peers {
            let addr = SocketAddrV6::new(mac.link_local(), AIRDROP_PORT, 0, iface.index);
            let mac_str = mac.to_string();
            if let Ok(Ok(Some(rx))) =
                tokio::time::timeout(Duration::from_secs(3), sender.discover(addr)).await
            {
                let mut peer = ApplePeer::from_discovered(
                    mac_str.clone(),
                    rx.computer_name,
                    rx.model_name,
                    addr,
                    DEFAULT_RECEIVER_FLAGS,
                    Some(mac_str),
                );
                peer.rssi = rssi;
                self.upsert_peer(peer).await;
            }
        }

        // 2. Browse mDNS on the AWDL interface until deadline
        if let Ok(mut browse) = Mdns::new(iface.index).browse().await {
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let Ok(Some(BrowseEvent::Found(found))) =
                    tokio::time::timeout(remaining, browse.events.recv()).await
                else {
                    break;
                };
                let addr = SocketAddrV6::new(found.addr, found.port, 0, iface.index);
                if let Ok(Ok(Some(rx))) =
                    tokio::time::timeout(Duration::from_secs(3), sender.discover(addr)).await
                {
                    let peer = ApplePeer::from_discovered(
                        found.instance,
                        rx.computer_name,
                        rx.model_name,
                        addr,
                        found.flags,
                        None,
                    );
                    self.upsert_peer(peer).await;
                }
            }
        }

        Ok(self.list_peers().await)
    }

    /// Sends files (`Payload::Files`) to an Apple peer via Owly AirDrop.
    pub async fn send_files(
        &self,
        peer_query: Option<&str>,
        files: Vec<PathBuf>,
        timeout_secs: u64,
    ) -> io::Result<Outcome> {
        let abs_files: Vec<PathBuf> = files
            .iter()
            .map(std::path::absolute)
            .collect::<Result<_, _>>()?;
        self.send_payload(peer_query, Payload::Files(abs_files), timeout_secs)
            .await
    }

    /// Sends URLs (`Payload::Urls`) to an Apple peer via Owly AirDrop (opens in Safari on iOS/macOS).
    pub async fn send_urls(
        &self,
        peer_query: Option<&str>,
        urls: Vec<String>,
        timeout_secs: u64,
    ) -> io::Result<Outcome> {
        self.send_payload(peer_query, Payload::Urls(urls), timeout_secs)
            .await
    }

    /// Sends text or clipboard content to an Apple peer via Owly AirDrop:
    /// - If the text is a web/mailto URL, sends as `Payload::Urls` so iOS opens it directly.
    /// - Otherwise writes a clean temporary `.txt` file and sends as `Payload::Files`.
    pub async fn send_text(
        &self,
        peer_query: Option<&str>,
        text: &str,
        timeout_secs: u64,
    ) -> io::Result<Outcome> {
        let trimmed = text.trim();
        if trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
            || trimmed.starts_with("mailto:")
        {
            return self
                .send_urls(peer_query, vec![trimmed.to_string()], timeout_secs)
                .await;
        }

        let temp_dir = tempfile::tempdir()?;
        let file_path = temp_dir.path().join("kdeconnect-shared-text.txt");
        std::fs::write(&file_path, text.as_bytes())?;
        self.send_files(peer_query, vec![file_path], timeout_secs)
            .await
    }

    /// Sends a KDE Connect Ping / FindMyPhone alert to the Apple peer by waking it via BLE
    /// and triggering an AirDrop prompt banner with the ping message.
    pub async fn send_ping(
        &self,
        peer_query: Option<&str>,
        message: Option<&str>,
        timeout_secs: u64,
    ) -> io::Result<Outcome> {
        let text = message.unwrap_or("Ping from KDE Connect!");
        let temp_dir = tempfile::tempdir()?;
        let file_path = temp_dir.path().join("KDE-Connect-Ping.txt");
        std::fs::write(&file_path, text.as_bytes())?;
        self.send_files(peer_query, vec![file_path], timeout_secs)
            .await
    }

    async fn send_payload(
        &self,
        peer_query: Option<&str>,
        payload: Payload,
        timeout_secs: u64,
    ) -> io::Result<Outcome> {
        let (iface, _) = self.ensure_interface(timeout_secs as u32 + 60).await?;
        let _ble_guard = advertise_ble(self.config.no_ble).await;
        let sender = Sender::new(sender::Config::new(
            self.config.computer_name.clone(),
            random_service_id()?,
        ))?;

        let target = self
            .resolve_target(&iface, &sender, peer_query, Duration::from_secs(timeout_secs))
            .await?;

        let (tx, mut rx) = mpsc::unbounded_channel();
        let events_tx = self.events_tx.clone();
        let peer_device_id = target.device_id.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                if let SenderEvent::Progress(p) = ev {
                    let _ = events_tx.send(BridgeEvent::TransferProgress {
                        peer_device_id: peer_device_id.clone(),
                        sent: p.sent,
                        total: p.total,
                    });
                }
            }
        });

        let addr = target
            .addr
            .ok_or_else(|| io::Error::other("resolved peer has no IPv6 socket address"))?;
        let res = sender.send(addr, &payload, target.flags, Some(tx)).await;

        // If the Wi-Fi card is in `exclusive` mode, release the lease right after the transfer
        // finishes so NetworkManager immediately reconnects normal Wi-Fi.
        if !self.is_shared_radio_mode().await {
            self.release_held_lease().await;
        }
        res
    }

    async fn resolve_target(
        &self,
        iface: &AwdlInterface,
        sender: &Sender,
        peer_query: Option<&str>,
        limit: Duration,
    ) -> io::Result<ApplePeer> {
        if let Some(q) = peer_query
            && let Some(cached) = self.get_peer(q).await
            && cached.addr.is_some()
        {
            return Ok(cached);
        }

        let deadline = tokio::time::Instant::now() + limit;
        let mut tried = HashSet::new();

        while tokio::time::Instant::now() < deadline {
            for (mac, rssi) in self.query_owlyd_peers().await {
                if tried.insert(mac) {
                    tracing::debug!(mac = %mac, "knocking AWDL peer for KDE Connect transfer");
                }
                let addr = SocketAddrV6::new(mac.link_local(), AIRDROP_PORT, 0, iface.index);
                let mac_str = mac.to_string();
                let wait = deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(Duration::from_secs(3));
                let Ok(Ok(Some(rx))) = tokio::time::timeout(wait, sender.discover(addr)).await
                else {
                    continue;
                };
                let mut peer = ApplePeer::from_discovered(
                    mac_str.clone(),
                    rx.computer_name,
                    rx.model_name,
                    addr,
                    DEFAULT_RECEIVER_FLAGS,
                    Some(mac_str),
                );
                peer.rssi = rssi;
                self.upsert_peer(peer.clone()).await;

                if peer_query.is_none_or(|q| {
                    q.eq_ignore_ascii_case(&peer.device_id)
                        || q.eq_ignore_ascii_case(&peer.name)
                        || q.eq_ignore_ascii_case(&peer.instance)
                }) {
                    return Ok(peer);
                }
            }

            if let Ok(mut browse) = Mdns::new(iface.index).browse().await {
                let slice = Duration::from_millis(800)
                    .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                if let Ok(Some(BrowseEvent::Found(found))) =
                    tokio::time::timeout(slice, browse.events.recv()).await
                {
                    let addr = SocketAddrV6::new(found.addr, found.port, 0, iface.index);
                    if let Ok(Ok(Some(rx))) =
                        tokio::time::timeout(Duration::from_secs(3), sender.discover(addr)).await
                    {
                        let peer = ApplePeer::from_discovered(
                            found.instance,
                            rx.computer_name,
                            rx.model_name,
                            addr,
                            found.flags,
                            None,
                        );
                        self.upsert_peer(peer.clone()).await;
                        if peer_query.is_none_or(|q| {
                            q.eq_ignore_ascii_case(&peer.device_id)
                                || q.eq_ignore_ascii_case(&peer.name)
                                || q.eq_ignore_ascii_case(&peer.instance)
                        }) {
                            return Ok(peer);
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(400)).await;
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no Apple AirDrop receiver answered /Discover within timeout",
        ))
    }
}

fn random_service_id() -> io::Result<String> {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(mdns::service_id(bytes))
}

fn random_tag() -> io::Result<[u8; 3]> {
    let mut tag = [0u8; 3];
    getrandom::fill(&mut tag).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(tag)
}

// --- BlueZ LE AirDrop Wake Advertiser (BLE-1, BLE-5) ---

const LE_ADV_MANAGER: &str = "org.bluez.LEAdvertisingManager1";
const BLUEZ_ADAPTER: &str = "org.bluez.Adapter1";
const DBUS_PROPERTIES: &str = "org.freedesktop.DBus.Properties";

static NEXT_ADVERT_ID: AtomicU32 = AtomicU32::new(0);

struct BleAdvertisement {
    data: Vec<u8>,
}

#[zbus::interface(name = "org.bluez.LEAdvertisement1")]
impl BleAdvertisement {
    fn release(&self) {}

    #[zbus(property, name = "Type")]
    fn kind(&self) -> &str {
        "peripheral"
    }

    #[zbus(property)]
    fn min_interval(&self) -> u32 {
        INTERVAL_MS
    }

    #[zbus(property)]
    fn max_interval(&self) -> u32 {
        INTERVAL_MS
    }

    #[zbus(property)]
    fn manufacturer_data(&self) -> HashMap<u16, ZValue<'_>> {
        HashMap::from([(APPLE_COMPANY_ID, ZValue::from(self.data.clone()))])
    }
}

pub struct BleAdvertGuard {
    conn: zbus::Connection,
    adapter: OwnedObjectPath,
    path: OwnedObjectPath,
}

impl Drop for BleAdvertGuard {
    fn drop(&mut self) {
        let conn = self.conn.clone();
        let adapter = self.adapter.clone();
        let path = self.path.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = conn
                    .call_method(
                        Some("org.bluez"),
                        adapter.as_str(),
                        Some(LE_ADV_MANAGER),
                        "UnregisterAdvertisement",
                        &(&path,),
                    )
                    .await;
                let _ = conn
                    .object_server()
                    .remove::<BleAdvertisement, _>(&path)
                    .await;
            });
        }
    }
}

pub async fn advertise_ble(skip: bool) -> Option<BleAdvertGuard> {
    if skip {
        return None;
    }
    let tag = random_tag().ok()?;
    let advert = Advert::anonymous(tag);
    let conn = zbus::Connection::system().await.ok()?;
    let objects = zbus::fdo::ObjectManagerProxy::builder(&conn)
        .destination("org.bluez")
        .ok()?
        .path("/")
        .ok()?
        .build()
        .await
        .ok()?
        .get_managed_objects()
        .await
        .ok()?;

    let adapter = objects
        .into_iter()
        .filter(|(_, ifaces)| ifaces.keys().any(|i| i.as_str() == LE_ADV_MANAGER))
        .map(|(p, _)| p)
        .next()?;

    // Ensure adapter is powered on
    let _ = conn
        .call_method(
            Some("org.bluez"),
            adapter.as_str(),
            Some(DBUS_PROPERTIES),
            "Set",
            &(BLUEZ_ADAPTER, "Powered", ZValue::from(true)),
        )
        .await;

    let n = NEXT_ADVERT_ID.fetch_add(1, Ordering::Relaxed);
    let path: OwnedObjectPath = ObjectPath::try_from(format!(
        "/io/github/t4t5/Owly/kdeconnect_advert{}_{n}",
        std::process::id()
    ))
    .ok()?
    .into();

    conn.object_server()
        .at(
            &path,
            BleAdvertisement {
                data: advert.manufacturer_data(),
            },
        )
        .await
        .ok()?;

    let options = HashMap::<&str, ZValue>::new();
    if conn
        .call_method(
            Some("org.bluez"),
            adapter.as_str(),
            Some(LE_ADV_MANAGER),
            "RegisterAdvertisement",
            &(&path, options),
        )
        .await
        .is_err()
    {
        let _ = conn
            .object_server()
            .remove::<BleAdvertisement, _>(&path)
            .await;
        return None;
    }

    Some(BleAdvertGuard {
        conn,
        adapter,
        path,
    })
}

/// Checks BlueZ managed objects for any nearby Apple device broadcasting an AirDrop
/// BLE advertisement (`Company ID 0x004c` with TLV type `0x05`), which iOS/macOS
/// transmits whenever the user opens the AirDrop / Share sheet.
/// Keeps a persistent D-Bus connection alive so BlueZ's `StartDiscovery` LE session
/// is not canceled when the function returns.
pub async fn check_ble_airdrop_wake_trigger() -> bool {
    static BLE_SCAN_CONN: std::sync::OnceLock<tokio::sync::Mutex<Option<zbus::Connection>>> =
        std::sync::OnceLock::new();
    let lock = BLE_SCAN_CONN.get_or_init(|| tokio::sync::Mutex::new(None));
    let mut guard = lock.lock().await;
    if guard.is_none() {
        *guard = zbus::Connection::system().await.ok();
    }
    let Some(conn) = guard.as_ref().cloned() else {
        return false;
    };
    drop(guard);

    let Ok(om) = zbus::fdo::ObjectManagerProxy::builder(&conn)
        .destination("org.bluez")
        .and_then(|b| b.path("/"))
        .map(|b| b.build())
    else {
        return false;
    };
    let Ok(om) = om.await else {
        return false;
    };
    let Ok(objects) = om.get_managed_objects().await else {
        return false;
    };

    for (path, ifaces) in &objects {
        if let Some(adapter) = ifaces.get(BLUEZ_ADAPTER) {
            let discovering = adapter
                .get("Discovering")
                .and_then(|v| v.downcast_ref::<bool>().ok())
                .unwrap_or(false);
            if !discovering {
                let mut filter = HashMap::<&str, ZValue>::new();
                filter.insert("Transport", ZValue::from("le"));
                filter.insert("DuplicateData", ZValue::from(true));
                let _ = conn
                    .call_method(
                        Some("org.bluez"),
                        path.as_str(),
                        Some(BLUEZ_ADAPTER),
                        "SetDiscoveryFilter",
                        &(filter,),
                    )
                    .await;
                let _ = conn
                    .call_method(
                        Some("org.bluez"),
                        path.as_str(),
                        Some(BLUEZ_ADAPTER),
                        "StartDiscovery",
                        &(),
                    )
                    .await;
            }
        }
    }

    for (dev_path, ifaces) in objects {
        let Some(dev) = ifaces.get("org.bluez.Device1") else {
            continue;
        };
        let Some(mfg) = dev.get("ManufacturerData") else {
            continue;
        };
        if let Ok(map) = <HashMap<u16, OwnedValue>>::try_from(mfg.clone())
            && let Some(apple_bytes_val) = map.get(&APPLE_COMPANY_ID)
            && let Ok(bytes) = <Vec<u8>>::try_from(apple_bytes_val.clone())
            && bytes.first() == Some(&0x05)
        {
            let paired = dev
                .get("Paired")
                .and_then(|v| v.downcast_ref::<bool>().ok())
                .unwrap_or(false);
            if !paired
                && let Some(adapter_val) = dev.get("Adapter")
                && let Ok(adapter_path) = adapter_val.downcast_ref::<ObjectPath>()
            {
                let _ = conn
                    .call_method(
                        Some("org.bluez"),
                        adapter_path.as_str(),
                        Some(BLUEZ_ADAPTER),
                        "RemoveDevice",
                        &(&dev_path,),
                    )
                    .await;
            }
            return true;
        }
    }
    false
}


