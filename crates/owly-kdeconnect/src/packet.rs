//! KDE Connect Protocol v8 `NetworkPacket` serialization, parsing, and
//! endpoint packet builders.
//!
//! Every KDE Connect wire packet is a single newline-terminated UTF-8 JSON
//! object:
//! ```json
//! {"id":1729800000000,"type":"kdeconnect.<domain>","body":{...},"payloadSize":123,"payloadTransferInfo":{"port":1739}}
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub const PROTOCOL_VERSION: i32 = 8;
pub const KDECONNECT_PORT: u16 = 1716;

// Protocol packet types
pub const PACKET_TYPE_IDENTITY: &str = "kdeconnect.identity";
pub const PACKET_TYPE_PAIR: &str = "kdeconnect.pair";

// Share & Clipboard packet types (backed by Owly AirDrop + AWDL)
pub const PACKET_TYPE_SHARE_REQUEST: &str = "kdeconnect.share.request";
pub const PACKET_TYPE_SHARE_REQUEST_UPDATE: &str = "kdeconnect.share.request.update";
pub const PACKET_TYPE_CLIPBOARD: &str = "kdeconnect.clipboard";
pub const PACKET_TYPE_CLIPBOARD_CONNECT: &str = "kdeconnect.clipboard.connect";
pub const PACKET_TYPE_CLIPBOARD_FILE: &str = "kdeconnect.clipboard.file";

// Ping & FindMyPhone (backed by BLE AirDrop Wake + AirDrop /Ask alert)
pub const PACKET_TYPE_PING: &str = "kdeconnect.ping";
pub const PACKET_TYPE_FINDMYPHONE_REQUEST: &str = "kdeconnect.findmyphone.request";

// Battery (backed by BlueZ org.bluez.Battery1 / BLE GATT 0x180F)
pub const PACKET_TYPE_BATTERY: &str = "kdeconnect.battery";

// Notifications (backed by Apple Notification Center Service ANCS + AirDrop /Ask prompts)
pub const PACKET_TYPE_NOTIFICATION: &str = "kdeconnect.notification";
pub const PACKET_TYPE_NOTIFICATION_REQUEST: &str = "kdeconnect.notification.request";
pub const PACKET_TYPE_NOTIFICATION_ACTION: &str = "kdeconnect.notification.action";
pub const PACKET_TYPE_NOTIFICATION_REPLY: &str = "kdeconnect.notification.reply";

// Telephony & PauseMusic (backed by ANCS CategoryIDIncomingCall + BlueZ HFP)
pub const PACKET_TYPE_TELEPHONY: &str = "kdeconnect.telephony";
pub const PACKET_TYPE_TELEPHONY_REQUEST_MUTE: &str = "kdeconnect.telephony.request_mute";

// Multimedia / MPRIS (backed by BlueZ org.bluez.MediaPlayer1 / Apple Media Service AMS)
pub const PACKET_TYPE_MPRIS: &str = "kdeconnect.mpris";
pub const PACKET_TYPE_MPRIS_REQUEST: &str = "kdeconnect.mpris.request";

// Contacts (backed by BlueZ OBEX PBAP org.bluez.obex.PhonebookAccess1)
pub const PACKET_TYPE_CONTACTS_REQUEST_ALL_UIDS_TIMESTAMPS: &str =
    "kdeconnect.contacts.request_all_uids_timestamps";
pub const PACKET_TYPE_CONTACTS_REQUEST_VCARDS_BY_UID: &str =
    "kdeconnect.contacts.request_vcards_by_uid";
pub const PACKET_TYPE_CONTACTS_RESPONSE_UIDS_TIMESTAMPS: &str =
    "kdeconnect.contacts.response_uids_timestamps";
pub const PACKET_TYPE_CONTACTS_RESPONSE_VCARDS: &str = "kdeconnect.contacts.response_vcards";

// SMS (backed by BlueZ OBEX MAP org.bluez.obex.MessageAccess1)
pub const PACKET_TYPE_SMS_MESSAGES: &str = "kdeconnect.sms.messages";
pub const PACKET_TYPE_SMS_REQUEST: &str = "kdeconnect.sms.request";
pub const PACKET_TYPE_SMS_REQUEST_CONVERSATIONS: &str = "kdeconnect.sms.request_conversations";
pub const PACKET_TYPE_SMS_REQUEST_CONVERSATION: &str = "kdeconnect.sms.request_conversation";

/// Incoming packet types that an Owly-backed Apple device accepts from KDE Connect.
pub const OWLY_INCOMING_CAPABILITIES: &[&str] = &[
    PACKET_TYPE_SHARE_REQUEST,
    PACKET_TYPE_SHARE_REQUEST_UPDATE,
    PACKET_TYPE_CLIPBOARD,
    PACKET_TYPE_CLIPBOARD_CONNECT,
    PACKET_TYPE_CLIPBOARD_FILE,
    PACKET_TYPE_PING,
    PACKET_TYPE_FINDMYPHONE_REQUEST,
    PACKET_TYPE_NOTIFICATION_REQUEST,
    PACKET_TYPE_NOTIFICATION_ACTION,
    PACKET_TYPE_NOTIFICATION_REPLY,
    PACKET_TYPE_TELEPHONY_REQUEST_MUTE,
    PACKET_TYPE_MPRIS_REQUEST,
    PACKET_TYPE_CONTACTS_REQUEST_ALL_UIDS_TIMESTAMPS,
    PACKET_TYPE_CONTACTS_REQUEST_VCARDS_BY_UID,
    PACKET_TYPE_SMS_REQUEST,
    PACKET_TYPE_SMS_REQUEST_CONVERSATIONS,
    PACKET_TYPE_SMS_REQUEST_CONVERSATION,
];

/// Outgoing packet types that an Owly-backed Apple device emits to KDE Connect.
pub const OWLY_OUTGOING_CAPABILITIES: &[&str] = &[
    PACKET_TYPE_SHARE_REQUEST,
    PACKET_TYPE_CLIPBOARD,
    PACKET_TYPE_CLIPBOARD_CONNECT,
    PACKET_TYPE_PING,
    PACKET_TYPE_BATTERY,
    PACKET_TYPE_NOTIFICATION,
    PACKET_TYPE_TELEPHONY,
    PACKET_TYPE_MPRIS,
    PACKET_TYPE_CONTACTS_RESPONSE_UIDS_TIMESTAMPS,
    PACKET_TYPE_CONTACTS_RESPONSE_VCARDS,
    PACKET_TYPE_SMS_MESSAGES,
];

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkPacket {
    pub id: Value,
    #[serde(rename = "type")]
    pub packet_type: String,
    #[serde(default)]
    pub body: Map<String, Value>,
    #[serde(rename = "payloadSize", skip_serializing_if = "Option::is_none")]
    pub payload_size: Option<i64>,
    #[serde(rename = "payloadTransferInfo", skip_serializing_if = "Option::is_none")]
    pub payload_transfer_info: Option<Map<String, Value>>,
}

impl NetworkPacket {
    pub fn new(packet_type: impl Into<String>, body: Value) -> Self {
        let body_map = match body {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        Self {
            id: Value::Number(now_millis().into()),
            packet_type: packet_type.into(),
            body: body_map,
            payload_size: None,
            payload_transfer_info: None,
        }
    }

    pub fn with_payload(mut self, size: i64, port: u16) -> Self {
        self.payload_size = Some(size);
        let mut info = Map::new();
        info.insert("port".into(), Value::Number(port.into()));
        self.payload_transfer_info = Some(info);
        self
    }

    /// Serializes to a single `\n`-terminated UTF-8 JSON line as required by `LanDeviceLink`.
    pub fn to_line(&self) -> Vec<u8> {
        let mut line = serde_json::to_vec(self).expect("valid NetworkPacket JSON");
        line.push(b'\n');
        line
    }

    pub fn from_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line.trim())
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.body.get(key)?.as_str()
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.body.get(key)?.as_bool()
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.body.get(key)?.as_i64()
    }

    pub fn payload_port(&self) -> Option<u16> {
        self.payload_transfer_info
            .as_ref()?
            .get("port")?
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
    }

    // --- Packet Builders ---

    /// Plaintext pre-TLS connection packet (`DeviceInfo::toConnectionPacket`).
    pub fn connection_packet(device_id: &str, device_name: &str) -> Self {
        Self::new(
            PACKET_TYPE_IDENTITY,
            json!({
                "deviceId": device_id,
                "deviceName": device_name,
                "protocolVersion": PROTOCOL_VERSION,
                "targetDeviceId": "",
                "targetProtocolVersion": PROTOCOL_VERSION,
            }),
        )
    }

    /// Post-TLS identity packet (`DeviceInfo::toIdentityPacket`).
    pub fn identity_packet(device_id: &str, device_name: &str, device_type: &str) -> Self {
        Self::new(
            PACKET_TYPE_IDENTITY,
            json!({
                "deviceId": device_id,
                "deviceName": device_name,
                "deviceType": device_type,
                "protocolVersion": PROTOCOL_VERSION,
                "incomingCapabilities": OWLY_INCOMING_CAPABILITIES,
                "outgoingCapabilities": OWLY_OUTGOING_CAPABILITIES,
            }),
        )
    }

    pub fn pair_request() -> Self {
        Self::new(
            PACKET_TYPE_PAIR,
            json!({
                "pair": true,
                "timestamp": now_secs(),
            }),
        )
    }

    pub fn pair_accept() -> Self {
        Self::new(
            PACKET_TYPE_PAIR,
            json!({
                "pair": true,
            }),
        )
    }

    pub fn share_file_header(
        filename: &str,
        size: u64,
        port: u16,
        number_of_files: usize,
        total_payload_size: u64,
    ) -> Self {
        let now = now_millis();
        Self::new(
            PACKET_TYPE_SHARE_REQUEST,
            json!({
                "filename": filename,
                "creationTime": now,
                "lastModified": now,
                "open": false,
                "numberOfFiles": number_of_files,
                "totalPayloadSize": total_payload_size,
            }),
        )
        .with_payload(size as i64, port)
    }

    pub fn share_url(url: &str) -> Self {
        Self::new(
            PACKET_TYPE_SHARE_REQUEST,
            json!({
                "url": url,
            }),
        )
    }

    pub fn share_text(text: &str) -> Self {
        Self::new(
            PACKET_TYPE_SHARE_REQUEST,
            json!({
                "text": text,
            }),
        )
    }

    pub fn clipboard(content: &str) -> Self {
        Self::new(
            PACKET_TYPE_CLIPBOARD,
            json!({
                "content": content,
            }),
        )
    }

    pub fn battery(charge: i32, is_charging: bool) -> Self {
        let threshold_event = if charge <= 15 && !is_charging { 1 } else { 0 };
        Self::new(
            PACKET_TYPE_BATTERY,
            json!({
                "currentCharge": charge,
                "isCharging": is_charging,
                "batteryQuantity": 1,
                "thresholdEvent": threshold_event,
            }),
        )
    }

    pub fn notification(
        id: &str,
        app_name: &str,
        title: &str,
        text: &str,
        is_clearable: bool,
        actions: &[String],
    ) -> Self {
        let ticker = if title.is_empty() {
            text.to_string()
        } else if text.is_empty() {
            title.to_string()
        } else {
            format!("{title}: {text}")
        };
        Self::new(
            PACKET_TYPE_NOTIFICATION,
            json!({
                "id": id,
                "appName": app_name,
                "title": title,
                "text": text,
                "ticker": ticker,
                "isClearable": is_clearable,
                "silent": false,
                "actions": actions,
            }),
        )
    }

    pub fn notification_cancel(id: &str) -> Self {
        Self::new(
            PACKET_TYPE_NOTIFICATION,
            json!({
                "id": id,
                "isCancel": true,
            }),
        )
    }

    pub fn telephony_ringing(phone_number: &str, contact_name: &str) -> Self {
        Self::new(
            PACKET_TYPE_TELEPHONY,
            json!({
                "event": "ringing",
                "phoneNumber": phone_number,
                "contactName": contact_name,
            }),
        )
    }

    pub fn telephony_cancel() -> Self {
        Self::new(
            PACKET_TYPE_TELEPHONY,
            json!({
                "event": "ringing",
                "isCancel": true,
            }),
        )
    }

    pub fn mpris_player_list(players: &[String]) -> Self {
        Self::new(
            PACKET_TYPE_MPRIS,
            json!({
                "playerList": players,
                "supportAlbumArtPayload": false,
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mpris_status(
        player: &str,
        title: &str,
        artist: &str,
        album: &str,
        is_playing: bool,
        pos_ms: i64,
        length_ms: i64,
        volume: i32,
    ) -> Self {
        Self::new(
            PACKET_TYPE_MPRIS,
            json!({
                "player": player,
                "title": title,
                "artist": artist,
                "album": album,
                "isPlaying": is_playing,
                "pos": pos_ms,
                "length": length_ms,
                "volume": volume,
                "canPlay": true,
                "canPause": true,
                "canGoNext": true,
                "canGoPrevious": true,
                "canSeek": true,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_share_packet_line() {
        let pkt = NetworkPacket::share_file_header("photo.jpg", 4096, 1739, 1, 4096);
        let bytes = pkt.to_line();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let parsed = NetworkPacket::from_line(std::str::from_utf8(&bytes).unwrap()).unwrap();
        assert_eq!(parsed.packet_type, PACKET_TYPE_SHARE_REQUEST);
        assert_eq!(parsed.get_str("filename"), Some("photo.jpg"));
        assert_eq!(parsed.payload_port(), Some(1739));
        assert_eq!(parsed.payload_size, Some(4096));
    }
}
