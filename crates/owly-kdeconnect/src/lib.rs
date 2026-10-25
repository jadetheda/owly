//! `owly-kdeconnect`: Owly (AWDL + AirDrop) and Apple BLE endpoint integration
//! for KDE Connect.
//!
//! Enables KDE Connect on Linux to discover and interact with Apple devices
//! (iPhone, iPad, Mac) without needing the KDE Connect app installed on the
//! remote device:
//! - **AirDrop + AWDL (`airdrop_bridge`)**: Bidirectional file transfer, URL
//!   sharing, clipboard/text sharing, interactive `/Ask` notifications, and
//!   BLE proximity wake via `owly-airdrop` and `owlyd`.
//! - **Apple BLE & OBEX (`apple_ble`)**: App-less iOS notifications and
//!   incoming call alerts via ANCS, media playback & metadata via AMS/AVRCP,
//!   battery reporting via `org.bluez.Battery1`, and Contacts/SMS via OBEX PBAP/MAP.
//! - **D-Bus Endpoint (`dbus`)**: Exposes `io.github.t4t5.Owly.KdeConnect1`
//!   at `/io/github/t4t5/Owly/KdeConnect` for KDE Connect's native `OwlyLinkProvider`
//!   C++ backend (`kdeconnect-kde/core/backends/owly`).
//! - **LAN Protocol v8 Bridge (`lan_bridge`)**: Speaks KDE Connect's native
//!   TLS v1.2/v1.3 `NetworkPacket` protocol to `127.0.0.1:1716` so unmodified
//!   `kdeconnectd` binaries work out of the box.

pub mod airdrop_bridge;
pub mod apple_ble;
pub mod dbus;
pub mod identity;
pub mod lan_bridge;
pub mod packet;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use airdrop_bridge::{BridgeConfig, OwlyAirdropBridge};
use lan_bridge::KdeConnectLanBridge;

#[derive(clap::Args, Debug, Clone)]
pub struct DaemonArgs {
    /// The AWDL interface managed by owlyd.
    #[arg(long, short, default_value = "awdl0")]
    pub iface: String,

    /// Computer name advertised over AirDrop (default: hostname).
    #[arg(long)]
    pub name: Option<String>,

    /// Directory where incoming AirDrop files are staged before KDE Connect moves them.
    #[arg(long)]
    pub dir: Option<PathBuf>,

    /// Port on the AWDL interface for the AirDrop TLS receiver (NET-4).
    #[arg(long, default_value_t = airdrop_bridge::DEFAULT_RECEIVE_PORT)]
    pub port: u16,

    /// Automatically accept all incoming AirDrop `/Ask` requests without prompting in KDE Notifications.
    #[arg(long)]
    pub auto_accept: bool,

    /// Do not automatically acquire an `awdl0` lease from `owlyd` until an existing one is up.
    #[arg(long)]
    pub no_auto_acquire: bool,

    /// Address of the local `kdeconnectd` TCP listener for the Protocol v8 LAN bridge.
    #[arg(long, default_value = "127.0.0.1:1716")]
    pub kdeconnect_addr: SocketAddr,

    /// Disable the Protocol v8 TCP/TLS bridge (use only when running the native C++ `OwlyLinkProvider` over D-Bus).
    #[arg(long)]
    pub no_lan_bridge: bool,

    /// Disable the `io.github.t4t5.Owly.KdeConnect1` session D-Bus service.
    #[arg(long)]
    pub no_dbus: bool,

    /// Don't send BLE AirDrop wake advertisements.
    #[arg(long)]
    pub no_ble: bool,

    /// Don't register mDNS `_airdrop._tcp.local.` announcements on the AWDL interface.
    #[arg(long)]
    pub no_mdns: bool,
}

pub async fn run_daemon(bus: Option<&str>, args: DaemonArgs) -> Result<ExitCode, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = BridgeConfig::default_with_dirs().map_err(|e| e.to_string())?;
    cfg.iface = args.iface;
    if let Some(name) = args.name {
        cfg.computer_name = name;
    }
    if let Some(dir) = args.dir {
        cfg.receive_dir = dir;
    }
    cfg.receive_port = args.port;
    cfg.auto_accept = args.auto_accept;
    cfg.auto_acquire_radio = !args.no_auto_acquire;
    cfg.bus_address = bus.map(String::from);
    cfg.no_ble = args.no_ble;
    cfg.no_mdns = args.no_mdns;

    let bridge = Arc::new(OwlyAirdropBridge::new(cfg));

    let _dbus_conn = if args.no_dbus {
        None
    } else {
        match dbus::serve_dbus(bridge.clone()).await {
            Ok(conn) => {
                tracing::info!(
                    service = dbus::DBUS_SERVICE_NAME,
                    path = dbus::DBUS_OBJECT_PATH,
                    "Registered Owly KDE Connect D-Bus service"
                );
                Some(conn)
            }
            Err(e) => {
                tracing::warn!("Could not register session D-Bus service (continuing): {e}");
                None
            }
        }
    };

    if !args.no_lan_bridge {
        let lan = Arc::new(KdeConnectLanBridge::new(
            bridge.clone(),
            args.kdeconnect_addr,
        ));
        tokio::spawn(async move {
            let _ = lan.run().await;
        });
    }

    let rx_bridge = bridge.clone();
    tokio::spawn(async move {
        loop {
            if rx_bridge.is_shared_radio_mode().await || !rx_bridge.config().auto_acquire_radio {
                // In `shared` radio mode (or when managing an external awdl0 lease), normal Wi-Fi
                // stays connected simultaneously, so we keep the AirDrop receiver open 24/7.
                if let Err(e) = rx_bridge.clone().start_receiver_window(0).await {
                    tracing::debug!("Waiting for AWDL interface ({e}); retrying in 5s...");
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            } else {
                // In `exclusive` radio mode, keep normal Wi-Fi connected while idle and automatically
                // open a 90-second AirDrop receiver window whenever an iPhone/Mac broadcasts a BLE
                // AirDrop wake advertisement (`0x004c` type `0x05`) or if `awdl0` is already up.
                if airdrop_bridge::AwdlInterface::lookup(&rx_bridge.config().iface).is_ok()
                    || airdrop_bridge::check_ble_airdrop_wake_trigger().await
                {
                    tracing::info!("Detected AirDrop activity; opening 90s AWDL receiver window");
                    if let Err(e) = rx_bridge.clone().start_receiver_window(90).await {
                        tracing::warn!("AWDL receiver window failed to start: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                    rx_bridge.release_held_lease().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    });

    let _ = tokio::signal::ctrl_c().await;
    Ok(ExitCode::SUCCESS)
}
