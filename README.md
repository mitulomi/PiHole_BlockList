# PiHole Blocklist Aggregator

![Update Blocklist](https://github.com/mitulomi/PiHole_BlockList/actions/workflows/update.yml/badge.svg)
![License](https://img.shields.io/github/license/mitulomi/PiHole_BlockList)
![Size](https://img.shields.io/github/repo-size/mitulomi/PiHole_BlockList)

Ein vollautomatischer, intelligenter Aggregator für Pi-hole Blocklisten. 

Dieses Projekt wurde entwickelt, um Pi-hole Instanzen (insbesondere auf schwächerer Hardware wie Raspberry Pi Zero/Orange Pi) vor Überlastung und **"Database locked"** Fehlern zu schützen, die durch das Einbinden zu vieler einzelner Listen entstehen.

---

## Die Blockliste (Raw Link)

Füge einfach diese **eine URL** in deinem Pi-hole hinzu. Sie enthält bereits über 1 Million bereinigte Domains.

```text
[https://raw.githubusercontent.com/mitulomi/PiHole_BlockList/main/pihole_blocklist.txt](https://raw.githubusercontent.com/mitulomi/PiHole_BlockList/main/pihole_blocklist.txt)
