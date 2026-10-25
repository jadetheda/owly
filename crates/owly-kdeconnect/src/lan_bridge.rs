//! Stock `kdeconnectd` Protocol v8 LAN Bridge (`127.0.0.1:1716`).
//!
//! Connects each discovered Apple peer (`ApplePeer` / `BluezAppleDevice`) directly to
//! `kdeconnectd`'s `LanLinkProvider` TCP port `1716`, completes KDE Connect's
//! reverse-role TLS handshake (`LanLinkProvider::tcpPacketReceived` -> `startClientEncryption()`),
//! handles `kdeconnect.pair`, and bridges:
//! - Incoming AirDrop files -> TLS payload transfer server + `kdeconnect.share.request`
//! - Incoming AirDrop URLs -> `kdeconnect.share.request` (`url`) + `kdeconnect.clipboard`
//! - Incoming AirDrop `/Ask` -> interactive `kdeconnect.notification` with `Accept`/`Decline` actions
//! - Outgoing KDE Connect file shares (`CompositeUploadJob`) -> TLS download + Owly AirDrop `send_files`
//! - Outgoing KDE Connect URL/text/clipboard shares -> Owly AirDrop `send_urls` / `send_text`
//! - Outgoing KDE Connect Ping / FindMyPhone -> BLE Wake + AirDrop alert
//! - BlueZ Battery, ANCS Notifications/Calls, AMS/MediaPlayer1 MPRIS, and OBEX PBAP Contacts.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::airdrop_bridge::{ApplePeer, BridgeEvent, OwlyAirdropBridge};
use crate::apple_ble::{
    empty_sms_messages_packet, execute_bluez_media_action, pull_obex_contacts,
    read_bluez_media_status, scan_bluez_apple_devices, send_ancs_action,
};
use crate::identity::DeviceIdentity;
use crate::packet::{
    KDECONNECT_PORT, NetworkPacket, PACKET_TYPE_CLIPBOARD, PACKET_TYPE_CLIPBOARD_CONNECT,
    PACKET_TYPE_CONTACTS_REQUEST_ALL_UIDS_TIMESTAMPS, PACKET_TYPE_CONTACTS_REQUEST_VCARDS_BY_UID,
    PACKET_TYPE_FINDMYPHONE_REQUEST, PACKET_TYPE_MPRIS_REQUEST, PACKET_TYPE_NOTIFICATION_ACTION,
    PACKET_TYPE_NOTIFICATION_REQUEST, PACKET_TYPE_PAIR, PACKET_TYPE_PING,
    PACKET_TYPE_SHARE_REQUEST, PACKET_TYPE_SMS_REQUEST_CONVERSATION,
    PACKET_TYPE_SMS_REQUEST_CONVERSATIONS, PACKET_TYPE_TELEPHONY_REQUEST_MUTE,
};

pub struct KdeConnectLanBridge {
    airdrop: Arc<OwlyAirdropBridge>,
    kdeconnect_addr: SocketAddr,
    sessions: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<NetworkPacket>>>>,
}

impl KdeConnectLanBridge {
    pub fn new(airdrop: Arc<OwlyAirdropBridge>, kdeconnect_addr: SocketAddr) -> Self {
        Self {
            airdrop,
            kdeconnect_addr,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Runs the LAN bridge loop:
    /// 1. Subscribes to `OwlyAirdropBridge` events (`PeerUpdated`, `IncomingAsk`, `FilesReceived`, `UrlsReceived`).
    /// 2. Periodically polls BlueZ Apple devices (`Battery1`, `MediaPlayer1`, ANCS).
    /// 3. Maintains a live TLS session to `kdeconnectd` (`127.0.0.1:1716`) for each Apple peer.
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        // Ensure a default virtual Apple AirDrop endpoint is always registered even before a
        // specific phone is discovered, so the user can immediately click "Send File" in KDE
        // Connect to wake nearby iPhones over BLE and send via AirDrop!
        let default_peer = ApplePeer {
            device_id: crate::identity::derive_device_id("owly-airdrop- nearby"),
            instance: "airdrop-any".into(),
            name: "AirDrop (Owly)".into(),
            model: "iPhone".into(),
            device_type: "phone".into(),
            mac: None,
            addr: None,
            flags: crate::airdrop_bridge::DEFAULT_RECEIVER_FLAGS,
            rssi: None,
            paired: true,
        };
        self.ensure_peer_session(default_peer).await;

        let mut bridge_rx = self.airdrop.subscribe();
        let bridge_self = self.clone();

        // Spawn BlueZ battery/device poller
        let ble_self = self.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(devs) = scan_bluez_apple_devices().await {
                    for dev in devs {
                        if !dev.connected {
                            continue;
                        }
                        let peer = ApplePeer {
                            device_id: dev.device_id.clone(),
                            instance: dev.address.clone(),
                            name: dev.name.clone(),
                            model: "iPhone".into(),
                            device_type: "phone".into(),
                            mac: Some(dev.address.clone()),
                            addr: None,
                            flags: crate::airdrop_bridge::DEFAULT_RECEIVER_FLAGS,
                            rssi: None,
                            paired: true,
                        };
                        ble_self.ensure_peer_session(peer).await;
                        if let Some(batt) = dev.battery_percentage {
                            ble_self
                                .send_to_kdeconnect(
                                    &dev.device_id,
                                    NetworkPacket::battery(batt, false),
                                )
                                .await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });

        while let Ok(ev) = bridge_rx.recv().await {
            match ev {
                BridgeEvent::PeerUpdated(peer) => {
                    bridge_self.ensure_peer_session(peer).await;
                }
                BridgeEvent::IncomingAsk {
                    id,
                    peer,
                    sender_name,
                    summary,
                    ..
                } => {
                    bridge_self.ensure_peer_session(peer.clone()).await;
                    let notif = NetworkPacket::notification(
                        &format!("airdrop-ask-{id}"),
                        "AirDrop (Owly)",
                        &sender_name,
                        &summary,
                        true,
                        &["Accept".to_string(), "Decline".to_string()],
                    );
                    bridge_self.send_to_kdeconnect(&peer.device_id, notif).await;
                }
                BridgeEvent::AskWithdrawn {
                    id,
                    peer_device_id,
                } => {
                    let cancel = NetworkPacket::notification_cancel(&format!("airdrop-ask-{id}"));
                    bridge_self
                        .send_to_kdeconnect(&peer_device_id, cancel)
                        .await;
                }
                BridgeEvent::FilesReceived { peer, paths, .. } => {
                    bridge_self.ensure_peer_session(peer.clone()).await;
                    bridge_self.forward_received_files(&peer, paths).await;
                }
                BridgeEvent::UrlsReceived { peer, urls, .. } => {
                    bridge_self.ensure_peer_session(peer.clone()).await;
                    for url in urls {
                        bridge_self
                            .send_to_kdeconnect(&peer.device_id, NetworkPacket::share_url(&url))
                            .await;
                        bridge_self
                            .send_to_kdeconnect(&peer.device_id, NetworkPacket::clipboard(&url))
                            .await;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub async fn send_to_kdeconnect(&self, device_id: &str, packet: NetworkPacket) {
        let sessions = self.sessions.lock().await;
        if let Some(tx) = sessions.get(device_id) {
            let _ = tx.send(packet);
        } else if let Some(tx) = sessions.values().next() {
            let _ = tx.send(packet);
        }
    }

    async fn ensure_peer_session(self: &Arc<Self>, peer: ApplePeer) {
        let mut sessions = self.sessions.lock().await;
        if sessions.contains_key(&peer.device_id) {
            return;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        sessions.insert(peer.device_id.clone(), tx);
        drop(sessions);

        let bridge = self.clone();
        tokio::spawn(async move {
            bridge.run_peer_session(peer, rx).await;
        });
    }

    async fn forward_received_files(&self, peer: &ApplePeer, paths: Vec<PathBuf>) {
        let Ok(identity) =
            DeviceIdentity::load_or_generate(&self.airdrop.config().state_dir, &peer.device_id)
        else {
            return;
        };
        let Ok(server_cfg) = identity.tls_server_config() else {
            return;
        };
        let acceptor = TlsAcceptor::from(server_cfg);

        let total_files = paths.len();
        let total_size: u64 = paths
            .iter()
            .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
            .sum();

        for path in paths {
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            let size = meta.len();
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("airdrop-file")
                .to_string();

            let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
                continue;
            };
            let Ok(local_addr) = listener.local_addr() else {
                continue;
            };
            let port = local_addr.port();

            let acceptor_clone = acceptor.clone();
            let path_clone = path.clone();
            tokio::spawn(async move {
                let Ok(Ok((tcp, _))) =
                    tokio::time::timeout(Duration::from_secs(20), listener.accept()).await
                else {
                    return;
                };
                let Ok(mut tls) = acceptor_clone.accept(tcp).await else {
                    return;
                };
                if let Ok(mut file) = tokio::fs::File::open(&path_clone).await {
                    let _ = tokio::io::copy(&mut file, &mut tls).await;
                    let _ = tls.flush().await;
                    let _ = tls.shutdown().await;
                }
            });

            let pkt = NetworkPacket::share_file_header(
                &filename,
                size,
                port,
                total_files,
                total_size,
            );
            self.send_to_kdeconnect(&peer.device_id, pkt).await;
        }
    }

    async fn run_peer_session(
        self: Arc<Self>,
        peer: ApplePeer,
        mut out_rx: mpsc::UnboundedReceiver<NetworkPacket>,
    ) {
        let Ok(identity) =
            DeviceIdentity::load_or_generate(&self.airdrop.config().state_dir, &peer.device_id)
        else {
            return;
        };
        let Ok(server_cfg) = identity.tls_server_config() else {
            return;
        };
        let acceptor = TlsAcceptor::from(server_cfg);

        let mut proto_ver: i64 = 8;

        loop {
            match TcpStream::connect(self.kdeconnect_addr).await {
                Ok(mut tcp) => {
                    let _ = tcp.set_nodelay(true);
                    tracing::debug!(
                        peer = %peer.name,
                        id = %peer.device_id,
                        addr = %self.kdeconnect_addr,
                        protocol = proto_ver,
                        "Connected to kdeconnectd TCP port; sending pre-TLS identity packet"
                    );

                    // Step 1: Send plaintext pre-TLS identity packet (valid for both v7 and v8)
                    let conn_pkt = NetworkPacket::connection_packet(
                        &peer.device_id,
                        &peer.name,
                        &peer.device_type,
                        proto_ver,
                    );
                    if let Err(e) = tcp.write_all(&conn_pkt.to_line()).await {
                        tracing::warn!("Failed writing pre-TLS packet to kdeconnectd: {e}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                    let _ = tcp.flush().await;

                    // Step 2: `kdeconnectd` calls `socket->startClientEncryption()`, so we act as TLS Server
                    let tls_stream = match tokio::time::timeout(
                        Duration::from_secs(5),
                        acceptor.accept(tcp),
                    )
                    .await
                    {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            tracing::warn!(
                                protocol = proto_ver,
                                "TLS handshake with kdeconnectd failed ({e}); toggling protocol v7/v8"
                            );
                            proto_ver = if proto_ver == 7 { 8 } else { 7 };
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            continue;
                        }
                        Err(_) => {
                            tracing::warn!(
                                protocol = proto_ver,
                                "Timed out waiting for kdeconnectd to start TLS; toggling protocol v7/v8"
                            );
                            proto_ver = if proto_ver == 7 { 8 } else { 7 };
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            continue;
                        }
                    };

                    let (read_half, mut write_half) = tokio::io::split(tls_stream);
                    let mut reader = BufReader::new(read_half).lines();

                    // Step 3: If speaking Protocol v8, send encrypted identity packet as well
                    if proto_ver >= 8 {
                        let id_pkt = NetworkPacket::identity_packet(
                            &peer.device_id,
                            &peer.name,
                            &peer.device_type,
                        );
                        if write_half.write_all(&id_pkt.to_line()).await.is_err()
                            || write_half.flush().await.is_err()
                        {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            continue;
                        }
                    }

                    // Step 4: Read `kdeconnectd`'s encrypted identity line
                    match tokio::time::timeout(Duration::from_secs(5), reader.next_line()).await {
                        Ok(Ok(Some(kde_line))) => {
                            tracing::info!(
                                peer = %peer.name,
                                id = %peer.device_id,
                                kde_host = %kde_line.trim(),
                                "Established KDE Connect TLS session with local kdeconnectd"
                            );
                        }
                        other => {
                            tracing::warn!(
                                protocol = proto_ver,
                                ?other,
                                "kdeconnectd closed TLS stream before sending identity; toggling protocol v7/v8"
                            );
                            proto_ver = if proto_ver == 7 { 8 } else { 7 };
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            continue;
                        }
                    }

                    // Ensure the device is paired in `kdeconnectd` by asking `kdeconnectd` to
                    // initiate `requestPair` over D-Bus if not already paired, then answering
                    // its `kdeconnect.pair` request with `pair_accept()`.
                    let dev_id_for_pair = peer.device_id.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        match ensure_kdeconnect_paired(&dev_id_for_pair).await {
                            Ok(already) => tracing::info!(
                                device_id = %dev_id_for_pair,
                                already_paired = already,
                                "Verified KDE Connect pairing state via D-Bus"
                            ),
                            Err(e) => tracing::debug!(
                                device_id = %dev_id_for_pair,
                                "D-Bus pairing check returned: {e}"
                            ),
                        }
                    });

                    // Also announce MPRIS player list
                    let _ = write_half
                        .write_all(
                            &NetworkPacket::mpris_player_list(&["Apple Media".into()]).to_line(),
                        )
                        .await;
                    let _ = write_half.flush().await;

                    loop {
                        tokio::select! {
                            Some(out_pkt) = out_rx.recv() => {
                                if write_half.write_all(&out_pkt.to_line()).await.is_err()
                                    || write_half.flush().await.is_err()
                                {
                                    break;
                                }
                            }
                            line_res = reader.next_line() => {
                                let Ok(Some(line)) = line_res else {
                                    tracing::warn!(peer = %peer.name, "kdeconnectd TLS connection closed; reconnecting");
                                    break;
                                };
                                tracing::debug!(peer = %peer.name, packet = %line, "Received packet from kdeconnectd");
                                let Ok(pkt) = NetworkPacket::from_line(&line) else {
                                    continue;
                                };
                                if let Some(reply) = self.handle_incoming_packet(&peer, &identity, pkt).await {
                                    let _ = write_half.write_all(&reply.to_line()).await;
                                    let _ = write_half.flush().await;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        addr = %self.kdeconnect_addr,
                        "Could not connect to kdeconnectd TCP listener ({e}); is kdeconnectd running?"
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn handle_incoming_packet(
        &self,
        peer: &ApplePeer,
        identity: &DeviceIdentity,
        pkt: NetworkPacket,
    ) -> Option<NetworkPacket> {
        let target_query = if peer.instance == "airdrop-any" {
            None
        } else {
            Some(peer.name.clone())
        };

        match pkt.packet_type.as_str() {
            PACKET_TYPE_PAIR => {
                // Only send `pair_accept` when `kdeconnectd` is requesting a new pair
                // (Protocol v8 pair requests include `"timestamp"` in `body`). Replying
                // `pair: true` to a `pair: true` confirmation when already paired causes
                // `kdeconnectd` to unpair the device!
                if pkt.get_bool("pair") == Some(true) && pkt.body.contains_key("timestamp") {
                    tracing::info!(peer = %peer.name, "Accepting incoming pair request from kdeconnectd");
                    return Some(NetworkPacket::pair_accept());
                }
            }
            PACKET_TYPE_SHARE_REQUEST => {
                if let Some(port) = pkt.payload_port() {
                    // File upload from KDE Connect (`CompositeUploadJob`)
                    let filename = pkt
                        .get_str("filename")
                        .unwrap_or("shared-file.bin")
                        .to_string();
                    let identity_clone = identity.clone();
                    let airdrop = self.airdrop.clone();
                    let host_ip = self.kdeconnect_addr.ip();
                    let query = target_query.clone();

                    tokio::spawn(async move {
                        if let Ok(path) =
                            download_kdeconnect_payload(host_ip, port, &filename, &identity_clone)
                                .await
                        {
                            let _ = airdrop.send_files(query.as_deref(), vec![path], 30).await;
                        }
                    });
                } else if let Some(url) = pkt.get_str("url") {
                    let url_str = url.to_string();
                    let airdrop = self.airdrop.clone();
                    let query = target_query.clone();
                    tokio::spawn(async move {
                        let _ = airdrop.send_urls(query.as_deref(), vec![url_str], 30).await;
                    });
                } else if let Some(text) = pkt.get_str("text") {
                    let text_str = text.to_string();
                    let airdrop = self.airdrop.clone();
                    let query = target_query.clone();
                    tokio::spawn(async move {
                        let _ = airdrop.send_text(query.as_deref(), &text_str, 30).await;
                    });
                }
            }
            PACKET_TYPE_CLIPBOARD | PACKET_TYPE_CLIPBOARD_CONNECT => {
                // Ignore automatic background clipboard sync (`clipboard.connect` on pair and
                // auto-sync on Ctrl+C) so copying text or pairing never interrupts Wi-Fi or
                // spams the iPhone with AirDrop prompts. Explicit text/link/file sharing in
                // KDE Connect uses `kdeconnect.share.request` above.
                tracing::debug!("Ignoring background clipboard sync packet (use Share to send via AirDrop)");
            }
            PACKET_TYPE_PING | PACKET_TYPE_FINDMYPHONE_REQUEST => {
                let msg = pkt.get_str("message").map(String::from);
                let airdrop = self.airdrop.clone();
                let query = target_query.clone();
                tokio::spawn(async move {
                    let _ = airdrop
                        .send_ping(query.as_deref(), msg.as_deref(), 30)
                        .await;
                });
            }
            PACKET_TYPE_NOTIFICATION_ACTION => {
                if let (Some(key), Some(action)) = (pkt.get_str("key"), pkt.get_str("action")) {
                    if let Some(ask_id_str) = key.strip_prefix("airdrop-ask-") {
                        if let Ok(ask_id) = ask_id_str.parse::<u64>() {
                            let accept = action.eq_ignore_ascii_case("accept");
                            self.airdrop.answer_ask(ask_id, accept).await;
                            return Some(NetworkPacket::notification_cancel(key));
                        }
                    } else if key.starts_with("ancs-") {
                        let positive = !action.eq_ignore_ascii_case("decline")
                            && !action.eq_ignore_ascii_case("dismiss")
                            && !action.eq_ignore_ascii_case("clear");
                        if let Ok(devs) = scan_bluez_apple_devices().await
                            && let Some(dev) = devs
                                .into_iter()
                                .find(|d| d.device_id == peer.device_id)
                            && let Some(cp) = dev.ancs_control_point_path
                        {
                            let _ = send_ancs_action(&cp, key, positive).await;
                        }
                    }
                }
            }
            PACKET_TYPE_NOTIFICATION_REQUEST => {
                if let Some(cancel_key) = pkt.get_str("cancel") {
                    if let Some(ask_id_str) = cancel_key.strip_prefix("airdrop-ask-") {
                        if let Ok(ask_id) = ask_id_str.parse::<u64>() {
                            self.airdrop.answer_ask(ask_id, false).await;
                        }
                    } else if cancel_key.starts_with("ancs-")
                        && let Ok(devs) = scan_bluez_apple_devices().await
                        && let Some(dev) =
                            devs.into_iter().find(|d| d.device_id == peer.device_id)
                        && let Some(cp) = dev.ancs_control_point_path
                    {
                        let _ = send_ancs_action(&cp, cancel_key, false).await;
                    }
                }
            }
            PACKET_TYPE_TELEPHONY_REQUEST_MUTE => {
                if let Ok(devs) = scan_bluez_apple_devices().await
                    && let Some(dev) = devs.into_iter().find(|d| d.device_id == peer.device_id)
                    && let Some(cp) = dev.ancs_control_point_path
                {
                    let _ = send_ancs_action(&cp, "ancs-0", false).await;
                }
                return Some(NetworkPacket::telephony_cancel());
            }
            PACKET_TYPE_MPRIS_REQUEST => {
                if pkt.get_bool("requestPlayerList") == Some(true) {
                    return Some(NetworkPacket::mpris_player_list(&["Apple Media".into()]));
                }
                if let Ok(devs) = scan_bluez_apple_devices().await
                    && let Some(dev) = devs
                        .into_iter()
                        .find(|d| d.device_id == peer.device_id || d.media_player_path.is_some())
                    && let Some(mp_path) = dev.media_player_path
                {
                    if pkt.get_str("action").is_some() {
                        let _ = execute_bluez_media_action(&mp_path, &pkt).await;
                    }
                    if let Ok(status_pkt) = read_bluez_media_status(&mp_path).await {
                        return Some(status_pkt);
                    }
                }
            }
            PACKET_TYPE_CONTACTS_REQUEST_ALL_UIDS_TIMESTAMPS
            | PACKET_TYPE_CONTACTS_REQUEST_VCARDS_BY_UID => {
                if let Some(bt_mac) = &peer.mac
                    && let Ok((uids_pkt, vcards_pkt)) = pull_obex_contacts(bt_mac).await
                {
                    if pkt.packet_type == PACKET_TYPE_CONTACTS_REQUEST_ALL_UIDS_TIMESTAMPS {
                        return Some(uids_pkt);
                    } else {
                        return Some(vcards_pkt);
                    }
                }
            }
            PACKET_TYPE_SMS_REQUEST_CONVERSATIONS | PACKET_TYPE_SMS_REQUEST_CONVERSATION => {
                return Some(empty_sms_messages_packet());
            }
            _ => {}
        }
        None
    }
}

/// Connects to `kdeconnectd`'s `CompositeUploadJob` TLS listener (`host:port`), downloads
/// the payload into a clean temporary directory under its original `filename`, and returns its path.
async fn download_kdeconnect_payload(
    host: std::net::IpAddr,
    port: u16,
    filename: &str,
    identity: &DeviceIdentity,
) -> io::Result<PathBuf> {
    let client_cfg = identity.tls_client_config()?;
    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect((host, port)).await?;
    let mut tls = connector.connect(identity.server_name(), tcp).await?;

    let safe_name = PathBuf::from(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("shared-file.bin")
        .to_string();

    let staging_dir = std::env::temp_dir().join(format!("owly-kdeconnect-tx-{}", std::process::id()));
    std::fs::create_dir_all(&staging_dir)?;
    let out_path = staging_dir.join(safe_name);

    let mut file = tokio::fs::File::create(&out_path).await?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = tls.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).await?;
    }
    file.flush().await?;
    Ok(out_path)
}

pub fn default_kdeconnect_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], KDECONNECT_PORT))
}

/// Checks `org.kde.kdeconnect.device.isPaired` on session D-Bus and, if not yet paired,
/// calls `requestPairing` on `kdeconnectd` so `kdeconnectd` sends a `kdeconnect.pair`
/// request that we immediately accept with `pair_accept()`.
async fn ensure_kdeconnect_paired(device_id: &str) -> zbus::Result<bool> {
    let conn = zbus::Connection::session().await?;
    let path = format!("/modules/kdeconnect/devices/{device_id}");
    if let Ok(reply) = conn
        .call_method(
            Some("org.kde.kdeconnect"),
            path.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.kde.kdeconnect.device", "isPaired"),
        )
        .await
        && let Ok(val) = reply.body().deserialize::<zbus::zvariant::OwnedValue>()
        && val.downcast_ref::<bool>() == Ok(true)
    {
        return Ok(true);
    }

    conn.call_method(
        Some("org.kde.kdeconnect"),
        path.as_str(),
        Some("org.kde.kdeconnect.device"),
        "requestPairing",
        &(),
    )
    .await?;
    Ok(false)
}


