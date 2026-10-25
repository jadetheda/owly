# `owly-kdeconnect`

`owly-kdeconnect` integrates Owly's AWDL (`owly-awdl` / `owlyd`) and AirDrop (`owly-airdrop`) stacks—alongside native iOS/macOS Bluetooth Low Energy & OBEX services—directly into **KDE Connect's endpoints**, so KDE Connect works with Apple devices **without installing or running the KDE Connect app on the phone**.

## What Works Without the KDE Connect App

| KDE Connect Plugin / Packet | Native Apple / Owly Endpoint Used | Direction |
|---|---|---|
| **Share (`kdeconnect.share.request`) — Files** | `owly-airdrop` (`Receiver` `/Ask` + `/Upload` CPIO/DVZip & `Sender` + BLE Wake Advert over `awdl0`) | Bidirectional (Dolphin / KDE Share $\leftrightarrow$ iOS/macOS native AirDrop sheet) |
| **Share (`kdeconnect.share.request`) — URLs** | `owly-airdrop` (`Offer::Urls` / `Payload::Urls`) | Bidirectional (opens natively in iOS Safari / Linux browser) |
| **Clipboard (`kdeconnect.clipboard`) & Text Share** | `owly-airdrop` (`Payload::Urls` for links, `.txt` AirDrop payload for text snippets; incoming URLs copied to KDE clipboard) | Bidirectional |
| **Notifications (`kdeconnect.notification`, `.action`, `.request`)** | Apple Notification Center Service (**ANCS** GATT `7905F431-B5CE-4E99-A40F-4B1E122D00D0`) + AirDrop `/Ask` interactive Accept/Decline prompts | Bidirectional (iOS notifications + action buttons in KDE Plasma) |
| **Telephony & Pause Music (`kdeconnect.telephony`)** | ANCS `CategoryIDIncomingCall` (`1`) + ANCS Negative Action / BlueZ HFP | Bidirectional (Incoming call banner, auto-pause desktop media, Mute/Decline call) |
| **Multimedia Control (`kdeconnect.mpris`, `.request`)** | BlueZ `org.bluez.MediaPlayer1` (AVRCP) & Apple Media Service (**AMS** GATT `89D3502B-0F36-433A-8EF4-C502AD55F8DC`) | Bidirectional (Track title/artist/album, Play/Pause/Next/Prev/Seek/Volume) |
| **Battery (`kdeconnect.battery`)** | BlueZ `org.bluez.Battery1` & BLE GATT Battery Service (`0x180F`) | iPhone/iPad $\rightarrow$ KDE Connect |
| **Ping / Find My Phone (`kdeconnect.ping`, `kdeconnect.findmyphone.request`)** | BLE AirDrop Wake Advert + AirDrop `/Ask` alert banner on lock/home screen | Bidirectional |
| **Contacts (`kdeconnect.contacts.*`)** | BlueZ OBEX Phonebook Access Profile (**PBAP** `org.bluez.obex.PhonebookAccess1`) | iPhone $\rightarrow$ KDE Connect (`vcards`) |
| **SMS (`kdeconnect.sms.*`)** | BlueZ OBEX Message Access Profile (**MAP** `org.bluez.obex.MessageAccess1`) | Bidirectional |

## Two Endpoint Integration Modes

1. **Native KDE Connect LinkProvider (`OwlyLinkProvider` in `kdeconnect-kde/core/backends/owly`)**:
   Talks to `owly-kdeconnectd` over the `io.github.t4t5.Owly.KdeConnect1` D-Bus interface (and directly to `owlyd`'s `io.github.t4t5.Owly.Radio1`).
2. **Stock `kdeconnectd` Protocol v8 LAN Bridge (`lan_bridge.rs`)**:
   Works with **unmodified** `kdeconnectd` packages! For every discovered Apple peer, `owly-kdeconnectd` generates a deterministic KDE Connect device identity (`^[a-zA-Z0-9_-]{32,38}$`) and P-256 self-signed certificate (`CN=<deviceId>`), connects to `127.0.0.1:1716`, completes KDE Connect's reverse-role TLS v1.2/v1.3 handshake, and translates all KDE Connect packets and TLS payload streams on the fly.
