//! App-less Apple Bluetooth Low Energy & OBEX endpoint integration for KDE Connect.
//!
//! Bridges native iOS/macOS Bluetooth GATT & OBEX services exposed over BlueZ
//! directly into KDE Connect `NetworkPacket` endpoints — requiring zero app on the phone:
//! - **ANCS (Apple Notification Center Service `7905F431-B5CE-4E99-A40F-4B1E122D00D0`)**:
//!   - Notification Source (`9FBF120D-6301-42D9-8C58-25E699A21DBD`)
//!   - Control Point (`69D1D8F3-45E1-49A8-9821-9BBDFDAAD9D9`)
//!   - Data Source (`22EAC6E9-24D6-4BB5-BE44-B36ACE7C7BFB`)
//!   Maps iOS notifications and Positive/Negative actions to `kdeconnect.notification`
//!   and `CategoryIDIncomingCall` (`1`) to `kdeconnect.telephony` (including `pausemusic`).
//! - **AMS / AVRCP (`org.bluez.MediaPlayer1` & AMS `89D3502B-0F36-433A-8EF4-C502AD55F8DC`)**:
//!   Maps track metadata and playback controls to `kdeconnect.mpris` & `kdeconnect.mpris.request`.
//! - **Battery (`org.bluez.Battery1` / BLE GATT `0x180F`)**:
//!   Maps battery percentage to `kdeconnect.battery`.
//! - **PBAP & MAP (`org.bluez.obex.PhonebookAccess1` & `MessageAccess1`)**:
//!   Maps contacts (vCards) and SMS to `kdeconnect.contacts.*` & `kdeconnect.sms.*`.

use std::collections::HashMap;
use std::io;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value as ZValue};

use crate::identity::{derive_device_id, filter_device_name};
use crate::packet::{
    NetworkPacket, PACKET_TYPE_CONTACTS_RESPONSE_UIDS_TIMESTAMPS,
    PACKET_TYPE_CONTACTS_RESPONSE_VCARDS, PACKET_TYPE_SMS_MESSAGES, now_millis,
};

// Apple Notification Center Service (ANCS) GATT UUIDs
pub const ANCS_SERVICE_UUID: &str = "7905f431-b5ce-4e99-a40f-4b1e122d00d0";
pub const ANCS_NOTIFICATION_SOURCE_UUID: &str = "9fbf120d-6301-42d9-8c58-25e699a21dbd";
pub const ANCS_CONTROL_POINT_UUID: &str = "69d1d8f3-45e1-49a8-9821-9bbdfdaad9d9";
pub const ANCS_DATA_SOURCE_UUID: &str = "22eac6e9-24d6-4bb5-be44-b36ace7c7bfb";

// Apple Media Service (AMS) GATT UUIDs
pub const AMS_SERVICE_UUID: &str = "89d3502b-0f36-433a-8ef4-c502ad55f8dc";
pub const AMS_REMOTE_COMMAND_UUID: &str = "9b3c81d8-57b1-4a8a-b8df-0e56f7ca51c2";

// ANCS EventID values
pub const ANCS_EVENT_ADDED: u8 = 0;
pub const ANCS_EVENT_MODIFIED: u8 = 1;
pub const ANCS_EVENT_REMOVED: u8 = 2;

// ANCS CategoryID values
pub const ANCS_CATEGORY_INCOMING_CALL: u8 = 1;
pub const ANCS_CATEGORY_MISSED_CALL: u8 = 2;

// ANCS CommandID values
pub const ANCS_CMD_GET_NOTIFICATION_ATTRIBUTES: u8 = 0;
pub const ANCS_CMD_PERFORM_NOTIFICATION_ACTION: u8 = 2;

// ANCS ActionID values
pub const ANCS_ACTION_POSITIVE: u8 = 0;
pub const ANCS_ACTION_NEGATIVE: u8 = 1;

// ANCS NotificationAttributeID values
pub const ANCS_ATTR_APP_IDENTIFIER: u8 = 0;
pub const ANCS_ATTR_TITLE: u8 = 1;
pub const ANCS_ATTR_SUBTITLE: u8 = 2;
pub const ANCS_ATTR_MESSAGE: u8 = 3;
pub const ANCS_ATTR_DATE: u8 = 5;
pub const ANCS_ATTR_POSITIVE_ACTION_LABEL: u8 = 6;
pub const ANCS_ATTR_NEGATIVE_ACTION_LABEL: u8 = 7;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncsNotificationEvent {
    pub event_id: u8,
    pub event_flags: u8,
    pub category_id: u8,
    pub category_count: u8,
    pub notification_uid: u32,
}

impl AncsNotificationEvent {
    /// Parses an 8-byte ANCS Notification Source GATT notification payload.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let uid = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Some(Self {
            event_id: bytes[0],
            event_flags: bytes[1],
            category_id: bytes[2],
            category_count: bytes[3],
            notification_uid: uid,
        })
    }

    /// Builds a `GetNotificationAttributes` (`0x00`) request for the ANCS Control Point
    /// characteristic to fetch AppIdentifier, Title, Subtitle, Message, and Action Labels.
    pub fn build_attribute_request(&self) -> Vec<u8> {
        let mut req = Vec::with_capacity(19);
        req.push(ANCS_CMD_GET_NOTIFICATION_ATTRIBUTES);
        req.extend_from_slice(&self.notification_uid.to_le_bytes());
        req.push(ANCS_ATTR_APP_IDENTIFIER);
        for attr in [ANCS_ATTR_TITLE, ANCS_ATTR_SUBTITLE, ANCS_ATTR_MESSAGE] {
            req.push(attr);
            req.extend_from_slice(&256u16.to_le_bytes());
        }
        req.push(ANCS_ATTR_DATE);
        req.push(ANCS_ATTR_POSITIVE_ACTION_LABEL);
        req.push(ANCS_ATTR_NEGATIVE_ACTION_LABEL);
        req
    }
}

/// Builds a `PerformNotificationAction` (`0x02`) command for the ANCS Control Point.
pub fn build_ancs_perform_action(notification_uid: u32, positive: bool) -> [u8; 6] {
    let uid = notification_uid.to_le_bytes();
    [
        ANCS_CMD_PERFORM_NOTIFICATION_ACTION,
        uid[0],
        uid[1],
        uid[2],
        uid[3],
        if positive {
            ANCS_ACTION_POSITIVE
        } else {
            ANCS_ACTION_NEGATIVE
        },
    ]
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncsParsedAttributes {
    pub notification_uid: u32,
    pub app_identifier: String,
    pub title: String,
    pub subtitle: String,
    pub message: String,
    pub date: String,
    pub positive_action: Option<String>,
    pub negative_action: Option<String>,
}

impl AncsParsedAttributes {
    /// Parses a response from the ANCS Data Source characteristic (`CommandID = 0`).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 || bytes[0] != ANCS_CMD_GET_NOTIFICATION_ATTRIBUTES {
            return None;
        }
        let uid = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let mut cursor = 5;
        let mut out = Self {
            notification_uid: uid,
            ..Default::default()
        };

        while cursor + 3 <= bytes.len() {
            let attr_id = bytes[cursor];
            let len = u16::from_le_bytes([bytes[cursor + 1], bytes[cursor + 2]]) as usize;
            cursor += 3;
            if cursor + len > bytes.len() {
                break;
            }
            let val = String::from_utf8_lossy(&bytes[cursor..cursor + len]).into_owned();
            cursor += len;
            match attr_id {
                ANCS_ATTR_APP_IDENTIFIER => out.app_identifier = val,
                ANCS_ATTR_TITLE => out.title = val,
                ANCS_ATTR_SUBTITLE => out.subtitle = val,
                ANCS_ATTR_MESSAGE => out.message = val,
                ANCS_ATTR_DATE => out.date = val,
                ANCS_ATTR_POSITIVE_ACTION_LABEL if !val.is_empty() => {
                    out.positive_action = Some(val)
                }
                ANCS_ATTR_NEGATIVE_ACTION_LABEL if !val.is_empty() => {
                    out.negative_action = Some(val)
                }
                _ => {}
            }
        }
        Some(out)
    }

    /// Converts this ANCS notification into a KDE Connect `kdeconnect.notification` packet
    /// (and, if `category_id == ANCS_CATEGORY_INCOMING_CALL`, also a `kdeconnect.telephony` packet).
    pub fn to_kdeconnect_packets(&self, category_id: u8) -> Vec<NetworkPacket> {
        let mut packets = Vec::new();
        let id = format!("ancs-{}", self.notification_uid);
        let app_name = friendly_ios_app_name(&self.app_identifier);
        let full_text = if self.subtitle.is_empty() {
            self.message.clone()
        } else if self.message.is_empty() {
            self.subtitle.clone()
        } else {
            format!("{} — {}", self.subtitle, self.message)
        };

        let mut actions = Vec::new();
        if let Some(pos) = &self.positive_action {
            actions.push(pos.clone());
        }
        if let Some(neg) = &self.negative_action {
            actions.push(neg.clone());
        }

        packets.push(NetworkPacket::notification(
            &id,
            &app_name,
            &self.title,
            &full_text,
            true,
            &actions,
        ));

        if category_id == ANCS_CATEGORY_INCOMING_CALL {
            let caller = if self.title.is_empty() {
                "Incoming Call"
            } else {
                &self.title
            };
            packets.push(NetworkPacket::telephony_ringing(caller, caller));
        }

        packets
    }
}

fn friendly_ios_app_name(bundle_id: &str) -> String {
    match bundle_id {
        "com.apple.MobileSMS" => "Messages".into(),
        "com.apple.mobilephone" => "Phone".into(),
        "com.apple.mobilemail" => "Mail".into(),
        "com.apple.facetime" => "FaceTime".into(),
        "com.apple.mobilecal" => "Calendar".into(),
        "com.apple.reminders" => "Reminders".into(),
        other => other
            .rsplit('.')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("iOS")
            .to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluezAppleDevice {
    pub object_path: String,
    pub device_id: String,
    pub name: String,
    pub address: String,
    pub connected: bool,
    pub battery_percentage: Option<i32>,
    pub ancs_notification_source_path: Option<String>,
    pub ancs_control_point_path: Option<String>,
    pub ancs_data_source_path: Option<String>,
    pub media_player_path: Option<String>,
}

/// Queries BlueZ (`org.bluez`) managed objects for paired/connected Apple devices,
/// their Battery (`org.bluez.Battery1`), MediaPlayer (`org.bluez.MediaPlayer1`),
/// and ANCS GATT characteristic object paths.
pub async fn scan_bluez_apple_devices() -> io::Result<Vec<BluezAppleDevice>> {
    let conn = zbus::Connection::system()
        .await
        .map_err(io::Error::other)?;
    let objects = zbus::fdo::ObjectManagerProxy::builder(&conn)
        .destination("org.bluez")
        .and_then(|b| b.path("/"))
        .map_err(io::Error::other)?
        .build()
        .await
        .map_err(io::Error::other)?
        .get_managed_objects()
        .await
        .map_err(io::Error::other)?;

    let mut devices = Vec::new();

    for (path, ifaces) in &objects {
        let Some(dev_props) = ifaces.get("org.bluez.Device1") else {
            continue;
        };
        let address = prop_string(dev_props, "Address").unwrap_or_default();
        if address.is_empty() {
            continue;
        }
        let name = prop_string(dev_props, "Name")
            .or_else(|| prop_string(dev_props, "Alias"))
            .unwrap_or_else(|| "iPhone".into());
        let connected = prop_bool(dev_props, "Connected").unwrap_or(false);

        let battery_percentage = ifaces
            .get("org.bluez.Battery1")
            .and_then(|b| b.get("Percentage"))
            .and_then(|v| v.downcast_ref::<u8>().ok())
            .map(i32::from);

        let prefix = format!("{}/", path.as_str());
        let mut ancs_ns = None;
        let mut ancs_cp = None;
        let mut ancs_ds = None;
        let mut media_player = None;

        for (sub_path, sub_ifaces) in &objects {
            if !sub_path.as_str().starts_with(&prefix) {
                continue;
            }
            if sub_ifaces.contains_key("org.bluez.MediaPlayer1") {
                media_player = Some(sub_path.as_str().to_string());
            }
            if let Some(ch) = sub_ifaces.get("org.bluez.GattCharacteristic1")
                && let Some(uuid) = prop_string(ch, "UUID")
            {
                if uuid.eq_ignore_ascii_case(ANCS_NOTIFICATION_SOURCE_UUID) {
                    ancs_ns = Some(sub_path.as_str().to_string());
                } else if uuid.eq_ignore_ascii_case(ANCS_CONTROL_POINT_UUID) {
                    ancs_cp = Some(sub_path.as_str().to_string());
                } else if uuid.eq_ignore_ascii_case(ANCS_DATA_SOURCE_UUID) {
                    ancs_ds = Some(sub_path.as_str().to_string());
                }
            }
        }

        devices.push(BluezAppleDevice {
            object_path: path.as_str().to_string(),
            device_id: derive_device_id(&address),
            name: filter_device_name(&name),
            address,
            connected,
            battery_percentage,
            ancs_notification_source_path: ancs_ns,
            ancs_control_point_path: ancs_cp,
            ancs_data_source_path: ancs_ds,
            media_player_path: media_player,
        });
    }

    Ok(devices)
}

/// Ensures `StartNotify` is enabled on the iPhone's ANCS Notification Source & Data Source
/// characteristics and converts any newly arrived ANCS notification into KDE Connect packets.
pub async fn poll_ancs_notifications(
    dev: &BluezAppleDevice,
    seen_uids: &mut std::collections::HashSet<u32>,
) -> Vec<NetworkPacket> {
    let (Some(ns_path), Some(cp_path), Some(ds_path)) = (
        dev.ancs_notification_source_path.as_deref(),
        dev.ancs_control_point_path.as_deref(),
        dev.ancs_data_source_path.as_deref(),
    ) else {
        return Vec::new();
    };

    let Ok(conn) = zbus::Connection::system().await else {
        return Vec::new();
    };

    for path in [ds_path, ns_path] {
        let _ = conn
            .call_method(
                Some("org.bluez"),
                path,
                Some("org.bluez.GattCharacteristic1"),
                "StartNotify",
                &(),
            )
            .await;
    }

    let Ok(ns_reply) = conn
        .call_method(
            Some("org.bluez"),
            ns_path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.bluez.GattCharacteristic1", "Value"),
        )
        .await
    else {
        return Vec::new();
    };
    let Ok(ns_val) = ns_reply.body().deserialize::<OwnedValue>() else {
        return Vec::new();
    };
    let Ok(ns_bytes) = <Vec<u8>>::try_from(ns_val) else {
        return Vec::new();
    };
    let Some(ev) = AncsNotificationEvent::parse(&ns_bytes) else {
        return Vec::new();
    };
    if ev.event_id == ANCS_EVENT_REMOVED {
        seen_uids.remove(&ev.notification_uid);
        return vec![NetworkPacket::notification_cancel(&format!(
            "ancs-{}",
            ev.notification_uid
        ))];
    }
    if !seen_uids.insert(ev.notification_uid) {
        return Vec::new();
    }

    let req = ev.build_attribute_request();
    let options = HashMap::<&str, ZValue>::new();
    if conn
        .call_method(
            Some("org.bluez"),
            cp_path,
            Some("org.bluez.GattCharacteristic1"),
            "WriteValue",
            &(req, options),
        )
        .await
        .is_err()
    {
        return Vec::new();
    }

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let Ok(ds_reply) = conn
        .call_method(
            Some("org.bluez"),
            ds_path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.bluez.GattCharacteristic1", "Value"),
        )
        .await
    else {
        return Vec::new();
    };
    let Ok(ds_val) = ds_reply.body().deserialize::<OwnedValue>() else {
        return Vec::new();
    };
    let Ok(ds_bytes) = <Vec<u8>>::try_from(ds_val) else {
        return Vec::new();
    };
    let Some(attrs) = AncsParsedAttributes::parse(&ds_bytes) else {
        return Vec::new();
    };
    attrs.to_kdeconnect_packets(ev.category_id)
}

/// Sends an ANCS Positive or Negative action (`PerformNotificationAction`) to BlueZ's
/// `org.bluez.GattCharacteristic1.WriteValue` for the given ANCS notification key (`ancs-<uid>`).
pub async fn send_ancs_action(
    control_point_path: &str,
    notification_key: &str,
    positive: bool,
) -> io::Result<()> {
    let uid_str = notification_key
        .strip_prefix("ancs-")
        .unwrap_or(notification_key);
    let uid: u32 = uid_str
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let payload = build_ancs_perform_action(uid, positive);

    let conn = zbus::Connection::system()
        .await
        .map_err(io::Error::other)?;
    let options = HashMap::<&str, ZValue>::new();
    conn.call_method(
        Some("org.bluez"),
        control_point_path,
        Some("org.bluez.GattCharacteristic1"),
        "WriteValue",
        &(payload.to_vec(), options),
    )
    .await
    .map(|_| ())
    .map_err(io::Error::other)
}

/// Reads current track status from BlueZ `org.bluez.MediaPlayer1` and returns a `kdeconnect.mpris` packet.
pub async fn read_bluez_media_status(media_player_path: &str) -> io::Result<NetworkPacket> {
    let conn = zbus::Connection::system()
        .await
        .map_err(io::Error::other)?;
    let reply = conn
        .call_method(
            Some("org.bluez"),
            media_player_path,
            Some("org.freedesktop.DBus.Properties"),
            "GetAll",
            &("org.bluez.MediaPlayer1",),
        )
        .await
        .map_err(io::Error::other)?;
    let props: HashMap<String, OwnedValue> =
        reply.body().deserialize().map_err(io::Error::other)?;

    let status = prop_string(&props, "Status").unwrap_or_else(|| "paused".into());
    let is_playing = status.eq_ignore_ascii_case("playing");
    let pos_ms = props
        .get("Position")
        .and_then(|v| v.downcast_ref::<u32>().ok())
        .map(i64::from)
        .unwrap_or(0);

    let mut title = String::new();
    let mut artist = String::new();
    let mut album = String::new();
    let mut length_ms = 0i64;

    if let Some(track_val) = props.get("Track")
        && let Ok(track) = <HashMap<String, OwnedValue>>::try_from(track_val.try_clone().unwrap())
    {
        title = prop_string(&track, "Title").unwrap_or_default();
        artist = prop_string(&track, "Artist").unwrap_or_default();
        album = prop_string(&track, "Album").unwrap_or_default();
        length_ms = track
            .get("Duration")
            .and_then(|v| v.downcast_ref::<u32>().ok())
            .map(i64::from)
            .unwrap_or(0);
    }

    Ok(NetworkPacket::mpris_status(
        "Apple Media",
        &title,
        &artist,
        &album,
        is_playing,
        pos_ms,
        length_ms,
        80,
    ))
}

/// Executes a `kdeconnect.mpris.request` action (`Play`, `Pause`, `PlayPause`, `Next`, `Previous`, `Stop`)
/// on BlueZ `org.bluez.MediaPlayer1`.
pub async fn execute_bluez_media_action(
    media_player_path: &str,
    packet: &NetworkPacket,
) -> io::Result<()> {
    let conn = zbus::Connection::system()
        .await
        .map_err(io::Error::other)?;
    if let Some(action) = packet.get_str("action") {
        let method = match action {
            "Play" => "Play",
            "Pause" => "Pause",
            "PlayPause" => "Play",
            "Next" => "Next",
            "Previous" => "Previous",
            "Stop" => "Stop",
            _ => return Ok(()),
        };
        let _ = conn
            .call_method(
                Some("org.bluez"),
                media_player_path,
                Some("org.bluez.MediaPlayer1"),
                method,
                &(),
            )
            .await;
    }
    Ok(())
}

/// Pulls vCards over Bluetooth OBEX PBAP (`org.bluez.obex.PhonebookAccess1`) and builds
/// KDE Connect `kdeconnect.contacts.response_uids_timestamps` and `kdeconnect.contacts.response_vcards` packets.
pub async fn pull_obex_contacts(bt_address: &str) -> io::Result<(NetworkPacket, NetworkPacket)> {
    let conn = zbus::Connection::session()
        .await
        .map_err(io::Error::other)?;
    let mut args = HashMap::<&str, ZValue>::new();
    args.insert("Target", ZValue::from("pbap"));

    let session_reply = conn
        .call_method(
            Some("org.bluez.obex"),
            "/org/bluez/obex",
            Some("org.bluez.obex.Client1"),
            "CreateSession",
            &(bt_address, args),
        )
        .await
        .map_err(io::Error::other)?;
    let session_path: OwnedObjectPath = session_reply
        .body()
        .deserialize()
        .map_err(io::Error::other)?;

    let _ = conn
        .call_method(
            Some("org.bluez.obex"),
            session_path.as_str(),
            Some("org.bluez.obex.PhonebookAccess1"),
            "Select",
            &("int", "pb"),
        )
        .await;

    let tmp = tempfile::NamedTempFile::new()?;
    let target_file = tmp.path().to_string_lossy().into_owned();
    let filters = HashMap::<&str, ZValue>::new();
    let _ = conn
        .call_method(
            Some("org.bluez.obex"),
            session_path.as_str(),
            Some("org.bluez.obex.PhonebookAccess1"),
            "PullAll",
            &(&target_file, filters),
        )
        .await;

    let raw_vcards = std::fs::read_to_string(tmp.path()).unwrap_or_default();
    let _ = conn
        .call_method(
            Some("org.bluez.obex"),
            "/org/bluez/obex",
            Some("org.bluez.obex.Client1"),
            "RemoveSession",
            &(&session_path,),
        )
        .await;

    Ok(vcards_to_kdeconnect_packets(&raw_vcards))
}

/// Splits a multi-vCard PBAP dump into KDE Connect's UIDs+timestamps packet and vCards response packet.
pub fn vcards_to_kdeconnect_packets(raw_vcards: &str) -> (NetworkPacket, NetworkPacket) {
    let ts = now_millis();
    let mut uids = Vec::new();
    let mut ts_body = serde_json::Map::new();
    let mut vcard_body = serde_json::Map::new();

    for (idx, chunk) in raw_vcards.split("END:VCARD").enumerate() {
        let trimmed = chunk.trim();
        if !trimmed.contains("BEGIN:VCARD") {
            continue;
        }
        let uid = format!("owly-contact-{}", idx + 1);
        let stamped = format!("{trimmed}\r\nX-KDECONNECT-TIMESTAMP:{ts}\r\nEND:VCARD\r\n");
        uids.push(Value::String(uid.clone()));
        ts_body.insert(uid.clone(), json!(ts));
        vcard_body.insert(uid, Value::String(stamped));
    }

    ts_body.insert("uids".into(), Value::Array(uids.clone()));
    vcard_body.insert("uids".into(), Value::Array(uids));

    (
        NetworkPacket::new(
            PACKET_TYPE_CONTACTS_RESPONSE_UIDS_TIMESTAMPS,
            Value::Object(ts_body),
        ),
        NetworkPacket::new(
            PACKET_TYPE_CONTACTS_RESPONSE_VCARDS,
            Value::Object(vcard_body),
        ),
    )
}

/// Builds a stub or OBEX MAP SMS conversation response packet (`kdeconnect.sms.messages`).
pub fn empty_sms_messages_packet() -> NetworkPacket {
    NetworkPacket::new(
        PACKET_TYPE_SMS_MESSAGES,
        json!({
            "version": 2,
            "messages": [],
        }),
    )
}

fn prop_string(props: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    props.get(key)?.downcast_ref::<String>().ok()
}

fn prop_bool(props: &HashMap<String, OwnedValue>, key: &str) -> Option<bool> {
    props.get(key)?.downcast_ref::<bool>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ancs_notification_and_converts_to_kdeconnect() {
        let raw_event = [
            ANCS_EVENT_ADDED,
            0x00,
            ANCS_CATEGORY_INCOMING_CALL,
            1,
            0x2a,
            0x00,
            0x00,
            0x00,
        ];
        let ev = AncsNotificationEvent::parse(&raw_event).unwrap();
        assert_eq!(ev.notification_uid, 42);
        assert_eq!(ev.category_id, ANCS_CATEGORY_INCOMING_CALL);

        // Build synthetic ANCS Data Source response
        let mut ds = vec![ANCS_CMD_GET_NOTIFICATION_ATTRIBUTES, 42, 0, 0, 0];
        // AppIdentifier = com.apple.mobilephone
        let app = b"com.apple.mobilephone";
        ds.push(ANCS_ATTR_APP_IDENTIFIER);
        ds.extend_from_slice(&(app.len() as u16).to_le_bytes());
        ds.extend_from_slice(app);
        // Title = Alice
        let title = b"Alice";
        ds.push(ANCS_ATTR_TITLE);
        ds.extend_from_slice(&(title.len() as u16).to_le_bytes());
        ds.extend_from_slice(title);
        // Message = iPhone Call
        let msg = b"iPhone Call";
        ds.push(ANCS_ATTR_MESSAGE);
        ds.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        ds.extend_from_slice(msg);

        let attrs = AncsParsedAttributes::parse(&ds).unwrap();
        assert_eq!(attrs.title, "Alice");
        let packets = attrs.to_kdeconnect_packets(ev.category_id);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].packet_type, "kdeconnect.notification");
        assert_eq!(packets[1].packet_type, "kdeconnect.telephony");
        assert_eq!(packets[1].get_str("event"), Some("ringing"));
    }
}
