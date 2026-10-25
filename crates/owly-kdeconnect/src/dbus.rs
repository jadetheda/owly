//! D-Bus service `io.github.t4t5.Owly.KdeConnect1` on `/io/github/t4t5/Owly/KdeConnect`.
//!
//! Used by the native `OwlyLinkProvider` / `OwlyDeviceLink` backend in
//! `kdeconnect-kde/core/backends/owly`, as well as CLI tools and desktop widgets.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use owly_airdrop::proto::sender::Outcome;
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedValue, Value};

use crate::airdrop_bridge::{ApplePeer, BridgeEvent, OwlyAirdropBridge};
use crate::apple_ble::{scan_bluez_apple_devices, send_ancs_action};

pub const DBUS_SERVICE_NAME: &str = "io.github.t4t5.Owly.KdeConnect";
pub const DBUS_OBJECT_PATH: &str = "/io/github/t4t5/Owly/KdeConnect";
pub const DBUS_INTERFACE_NAME: &str = "io.github.t4t5.Owly.KdeConnect1";

pub struct OwlyKdeConnectDbus {
    bridge: Arc<OwlyAirdropBridge>,
}

impl OwlyKdeConnectDbus {
    pub fn new(bridge: Arc<OwlyAirdropBridge>) -> Self {
        Self { bridge }
    }
}

#[interface(name = "io.github.t4t5.Owly.KdeConnect1")]
impl OwlyKdeConnectDbus {
    /// Returns all known Apple peers (discovered via Owly AirDrop/AWDL and BlueZ).
    async fn list_peers(&self) -> Vec<HashMap<String, OwnedValue>> {
        let mut out: HashMap<String, HashMap<String, OwnedValue>> = HashMap::new();
        for peer in self.bridge.list_peers().await {
            out.insert(peer.device_id.clone(), peer_to_dict(&peer));
        }
        if let Ok(ble_devs) = scan_bluez_apple_devices().await {
            for dev in ble_devs {
                out.entry(dev.device_id.clone()).or_insert_with(|| {
                    let mut d = HashMap::new();
                    put_str(&mut d, "device_id", &dev.device_id);
                    put_str(&mut d, "name", &dev.name);
                    put_str(&mut d, "model", "iPhone");
                    put_str(&mut d, "device_type", "phone");
                    put_str(&mut d, "mac", &dev.address);
                    if let Some(batt) = dev.battery_percentage {
                        let _ = d.insert(
                            "battery".into(),
                            Value::from(batt).try_to_owned().unwrap(),
                        );
                    }
                    d
                });
            }
        }
        out.into_values().collect()
    }

    /// Triggers BLE AirDrop wake advertisement + AWDL/mDNS `/Discover` probe for `timeout_secs`.
    async fn discover_peers(&self, timeout_secs: u32) -> Vec<HashMap<String, OwnedValue>> {
        let _ = self.bridge.discover_peers(u64::from(timeout_secs.max(3))).await;
        self.list_peers().await
    }

    /// Sends one or more local files to `peer` (by `device_id`, `name`, `instance`, or empty for first peer)
    /// via Owly AirDrop (`/Discover` + `/Ask` + `/Upload`).
    async fn send_files(&self, peer: &str, file_paths: Vec<String>) -> (bool, String) {
        let query = if peer.trim().is_empty() {
            None
        } else {
            Some(peer.trim())
        };
        let paths: Vec<PathBuf> = file_paths.into_iter().map(PathBuf::from).collect();
        match self.bridge.send_files(query, paths, 30).await {
            Ok(Outcome::Delivered) => (true, "delivered".into()),
            Ok(Outcome::Declined) => (false, "declined by receiver".into()),
            Ok(Outcome::Failed(reason)) => (false, reason),
            Err(e) => (false, e.to_string()),
        }
    }

    /// Sends one or more URLs to `peer` via Owly AirDrop (`Payload::Urls`).
    async fn send_urls(&self, peer: &str, urls: Vec<String>) -> (bool, String) {
        let query = if peer.trim().is_empty() {
            None
        } else {
            Some(peer.trim())
        };
        match self.bridge.send_urls(query, urls, 30).await {
            Ok(Outcome::Delivered) => (true, "delivered".into()),
            Ok(Outcome::Declined) => (false, "declined by receiver".into()),
            Ok(Outcome::Failed(reason)) => (false, reason),
            Err(e) => (false, e.to_string()),
        }
    }

    /// Sends plain text or clipboard content to `peer` via Owly AirDrop.
    async fn send_text(&self, peer: &str, text: &str) -> (bool, String) {
        let query = if peer.trim().is_empty() {
            None
        } else {
            Some(peer.trim())
        };
        match self.bridge.send_text(query, text, 30).await {
            Ok(Outcome::Delivered) => (true, "delivered".into()),
            Ok(Outcome::Declined) => (false, "declined by receiver".into()),
            Ok(Outcome::Failed(reason)) => (false, reason),
            Err(e) => (false, e.to_string()),
        }
    }

    /// Sends a KDE Connect Ping / FindMyPhone alert to `peer`.
    async fn send_ping(&self, peer: &str, message: &str) -> (bool, String) {
        let query = if peer.trim().is_empty() {
            None
        } else {
            Some(peer.trim())
        };
        let msg = if message.trim().is_empty() {
            None
        } else {
            Some(message)
        };
        match self.bridge.send_ping(query, msg, 30).await {
            Ok(Outcome::Delivered) => (true, "delivered".into()),
            Ok(Outcome::Declined) => (true, "prompt shown on device".into()),
            Ok(Outcome::Failed(reason)) => (false, reason),
            Err(e) => (false, e.to_string()),
        }
    }

    /// Accepts or declines a pending incoming AirDrop `/Ask` transfer by its `transfer_id`.
    async fn answer_ask(&self, transfer_id: u64, accept: bool) -> bool {
        self.bridge.answer_ask(transfer_id, accept).await
    }

    /// Triggers an ANCS Positive or Negative notification action on the Apple peer over BLE GATT.
    async fn trigger_ancs_action(
        &self,
        peer_device_id: &str,
        notification_key: &str,
        positive: bool,
    ) -> bool {
        let Ok(devs) = scan_bluez_apple_devices().await else {
            return false;
        };
        let Some(dev) = devs
            .into_iter()
            .find(|d| d.device_id == peer_device_id || peer_device_id.is_empty())
        else {
            return false;
        };
        let Some(cp) = dev.ancs_control_point_path else {
            return false;
        };
        send_ancs_action(&cp, notification_key, positive).await.is_ok()
    }

    // --- D-Bus Signals emitted to KDE Connect's OwlyLinkProvider ---

    #[zbus(signal)]
    pub async fn peer_updated(
        emitter: &SignalEmitter<'_>,
        peer: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn incoming_ask(
        emitter: &SignalEmitter<'_>,
        transfer_id: u64,
        peer_device_id: String,
        sender_name: String,
        sender_model: String,
        summary: String,
        items: Vec<String>,
        is_url: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn files_received(
        emitter: &SignalEmitter<'_>,
        transfer_id: u64,
        peer_device_id: String,
        sender_name: String,
        paths: Vec<String>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn urls_received(
        emitter: &SignalEmitter<'_>,
        transfer_id: u64,
        peer_device_id: String,
        sender_name: String,
        urls: Vec<String>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn transfer_progress(
        emitter: &SignalEmitter<'_>,
        peer_device_id: String,
        sent: u64,
        total: u64,
    ) -> zbus::Result<()>;
}

pub fn peer_to_dict(peer: &ApplePeer) -> HashMap<String, OwnedValue> {
    let mut d = HashMap::new();
    put_str(&mut d, "device_id", &peer.device_id);
    put_str(&mut d, "instance", &peer.instance);
    put_str(&mut d, "name", &peer.name);
    put_str(&mut d, "model", &peer.model);
    put_str(&mut d, "device_type", &peer.device_type);
    if let Some(mac) = &peer.mac {
        put_str(&mut d, "mac", mac);
    }
    if let Some(addr) = &peer.addr {
        put_str(&mut d, "addr", &addr.to_string());
    }
    let _ = d.insert(
        "flags".into(),
        Value::from(peer.flags).try_to_owned().unwrap(),
    );
    d
}

fn put_str(d: &mut HashMap<String, OwnedValue>, k: &str, v: &str) {
    let _ = d.insert(k.to_string(), Value::from(v).try_to_owned().unwrap());
}

/// Starts the `io.github.t4t5.Owly.KdeConnect1` D-Bus service on the session bus and forwards
/// `BridgeEvent`s as D-Bus signals.
pub async fn serve_dbus(bridge: Arc<OwlyAirdropBridge>) -> zbus::Result<zbus::Connection> {
    let conn = zbus::connection::Builder::session()?
        .name(DBUS_SERVICE_NAME)?
        .serve_at(
            DBUS_OBJECT_PATH,
            OwlyKdeConnectDbus::new(bridge.clone()),
        )?
        .build()
        .await?;

    let mut rx = bridge.subscribe();
    let conn_clone = conn.clone();
    tokio::spawn(async move {
        let Ok(iface_ref) = conn_clone
            .object_server()
            .interface::<_, OwlyKdeConnectDbus>(DBUS_OBJECT_PATH)
            .await
        else {
            return;
        };
        let emitter = iface_ref.signal_emitter();
        while let Ok(ev) = rx.recv().await {
            match ev {
                BridgeEvent::PeerUpdated(peer) => {
                    let _ = OwlyKdeConnectDbus::peer_updated(emitter, peer_to_dict(&peer)).await;
                }
                BridgeEvent::IncomingAsk {
                    id,
                    peer,
                    sender_name,
                    sender_model,
                    summary,
                    items,
                    is_url,
                } => {
                    let _ = OwlyKdeConnectDbus::incoming_ask(
                        emitter,
                        id,
                        peer.device_id,
                        sender_name,
                        sender_model,
                        summary,
                        items,
                        is_url,
                    )
                    .await;
                }
                BridgeEvent::FilesReceived { id, peer, paths } => {
                    let path_strs = paths
                        .into_iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect();
                    let _ = OwlyKdeConnectDbus::files_received(
                        emitter,
                        id,
                        peer.device_id,
                        peer.name,
                        path_strs,
                    )
                    .await;
                }
                BridgeEvent::UrlsReceived { id, peer, urls } => {
                    let _ = OwlyKdeConnectDbus::urls_received(
                        emitter,
                        id,
                        peer.device_id,
                        peer.name,
                        urls,
                    )
                    .await;
                }
                BridgeEvent::TransferProgress {
                    peer_device_id,
                    sent,
                    total,
                } => {
                    let _ = OwlyKdeConnectDbus::transfer_progress(
                        emitter,
                        peer_device_id,
                        sent,
                        total,
                    )
                    .await;
                }
                _ => {}
            }
        }
    });

    Ok(conn)
}
