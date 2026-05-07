# Caddy + CrowdSec Reverse Proxy — Setup, Pflege, Stolpersteine

**Author:** René Wulff (wulffit.de) · **License:** MIT (see [`../LICENSE`](../LICENSE))
**Created:** 2026-04-26 · **Last updated:** 2026-05-06
**Tested with:** Caddy 2.10+, CrowdSec 1.7+, `caddy-crowdsec-bouncer` (hslatman), `caddy-l4` (mholt)

> **Pre-requisite-Doku fuer das ember-crowdsec Plugin.** Wer das Plugin produktiv einsetzen will, braucht zuerst einen funktionierenden Caddy + CrowdSec-Stack. Diese Anleitung ist ein vollstaendiger Setup-Guide aus realem Live-Einsatz inkl. der Stolpersteine, die nirgends in der offiziellen Doku stehen. Der Plugin-Tab im Ember-TUI greift direkt auf die LAPI zu, die hier eingerichtet wird.

---

# Von Zoraxy zu Caddy + CrowdSec

Pragmatische Migration für einen Heim-Server-Setup. Etwa **2–4 Stunden Arbeit** netto, wenn du konzentriert bleibst und nicht zwischendrin Container kompilierst.

Diese Anleitung baut auf einem schlanken LXC/VM mit Debian 12. Der gleiche Weg funktioniert auf Baremetal genauso.

---

## Was du am Ende hast

- **Caddy 2.10+** als Reverse Proxy (Ersatz für Zoraxy)
- Custom-Build mit zwei Plugins:
  - `caddy-l4` — TCP/UDP-Proxy für Dinge wie RustDesk
  - `caddy-crowdsec-bouncer` — automatisches Sperren bösartiger IPs
- **CrowdSec-Engine** parst die Caddy-Access-Logs und sperrt Angreifer
- **Let's Encrypt** vollautomatisch — keine manuelle ACME-Pflege
- Speicher-Footprint: ~50 MB RAM für Caddy + ~120 MB für CrowdSec

---

## Warum nicht einfach das Community-Script?

Es gibt das ProxmoxVE Community-Helper-Script, das in 30 Sekunden einen LXC mit Caddy hinstellt:
[community-scripts.github.io/ProxmoxVE](https://community-scripts.github.io/ProxmoxVE/scripts?id=caddy).

Das Script ist sauber gepflegt und ein guter Default — aber es installiert **Stock-Caddy aus dem Paket-Repo, ohne Plugins**. Caddy hat kein Plugin-System zur Laufzeit: Plugins müssen in die Binary einkompiliert sein. Heißt: Wer CrowdSec-Bouncer oder Layer-4 will, kommt um den eigenen Build nicht herum.

| Aspekt | Community-Script | Dieser Guide |
|--------|------------------|--------------|
| Caddy-Version | apt-Paket (jeweils stable) | Custom-Build via xcaddy |
| `caddy-l4` (TCP/UDP) | nein | ja |
| `caddy-crowdsec-bouncer` | **nein** | **ja** |
| ACME / Let's Encrypt | ja | ja |
| Auto-Update | `apt upgrade` | manueller xcaddy-Rebuild |
| Setup-Zeit | 1 Min | 30–45 Min (einmalig) |
| Pflegeaufwand | minimal | gering, aber bewusst |

**Empfehlung:**

- Du willst **nur** Reverse Proxy + Let's Encrypt, ohne weitere Plugins → **Community-Script nehmen** und glücklich sein. Du sparst dir die Build-Toolchain und kriegst Sicherheits-Updates per `apt upgrade`.
- Du willst **CrowdSec dazu** (so wie hier geplant) oder L4-Proxy für RustDesk → **diesen Guide nehmen**, der Custom-Build ist Pflicht.

Wenn du den Community-Script-LXC schon stehen hast und CrowdSec nachrüsten willst, kannst du im selben LXC einfach den Custom-Build drüberlegen (xcaddy installieren, neu bauen, `mv ./caddy /usr/bin/caddy`, `systemctl reload caddy`) — die Caddyfile + ACME-Zertifikate bleiben erhalten. Das ist sogar ein angenehmer Migrationspfad: erst Reverse Proxy stabil, später CrowdSec dazu.

---

## Voraussetzungen

| Was | Detail |
|-----|--------|
| OS | Debian 12 (CrowdSec hat offizielles Repo — auf Alpine ist es Bastelei) |
| Hardware | 1 GB RAM, 4 GB Disk, 1–2 Cores reicht |
| Netz | Public-IP, Port 80 + 443 von außen erreichbar |
| DNS | A-Records deiner Domains zeigen auf die Box |
| Root | Klar — `sudo` reicht auch |

---

## Schritt 1: System vorbereiten

```bash
apt update
apt install -y curl ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https git
```

---

## Schritt 2: Go installieren

`xcaddy` (das Build-Tool für Caddy mit Plugins) braucht Go ≥ 1.22.

```bash
curl -L https://go.dev/dl/go1.22.5.linux-amd64.tar.gz | tar -xz -C /usr/local
echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
export PATH=$PATH:/usr/local/go/bin
go version
# → go version go1.22.5 linux/amd64
```

---

## Schritt 3: xcaddy installieren

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/gpg.key' \
  | gpg --dearmor -o /usr/share/keyrings/caddy-xcaddy-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/debian.deb.txt' \
  | tee /etc/apt/sources.list.d/caddy-xcaddy.list
apt update && apt install -y xcaddy
```

---

## Schritt 4: Custom-Caddy bauen

Das ist der Moment, wo aus Standard-Caddy unser Reverse Proxy wird.

```bash
cd /tmp
xcaddy build \
  --with github.com/mholt/caddy-l4 \
  --with github.com/hslatman/caddy-crowdsec-bouncer/http \
  --with github.com/hslatman/caddy-crowdsec-bouncer/layer4 \
  --with github.com/hslatman/caddy-crowdsec-bouncer/appsec \
  --with github.com/hslatman/caddy-crowdsec-bouncer/crowdsec
```

Build dauert 5–10 Minuten. Das fertige Binary heißt `caddy` und liegt im aktuellen Verzeichnis.

```bash
mv ./caddy /usr/bin/caddy
caddy version
# → v2.10.x h1:...

# Plugins müssen auftauchen:
caddy list-modules | grep -E "crowdsec|layer4"
```

---

## Schritt 5: Caddy als systemd-Service

User und Verzeichnisse anlegen:

```bash
groupadd --system caddy
useradd --system \
  --gid caddy \
  --create-home \
  --home-dir /var/lib/caddy \
  --shell /usr/sbin/nologin \
  --comment "Caddy web server" \
  caddy

mkdir -p /etc/caddy /var/log/caddy
chown caddy:caddy /var/log/caddy
```

`/etc/systemd/system/caddy.service`:

```ini
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
EnvironmentFile=/etc/caddy/env
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Noch nicht starten — wir brauchen erst CrowdSec und Caddyfile.

---

## Schritt 6: CrowdSec installieren

```bash
curl -s https://install.crowdsec.net | bash
apt install -y crowdsec
```

### Welcher Token? Drei Stück, nicht verwechseln

CrowdSec unterscheidet drei verschiedene Tokens — die meisten Erst-Setups stolpern hier:

| Token | Wofür | Wie erzeugt | Hier gebraucht? |
|-------|-------|-------------|----------------|
| **Bouncer-Key** | Damit Caddy sich bei der lokalen LAPI authentifiziert | `cscli bouncers add <name>` | **Ja — das ist der Wert für `CROWDSEC_API_KEY` im nächsten Schritt.** |
| Engine-/Console-Token | Optional: Engine an `app.crowdsec.net` anbinden (Web-Dashboard) | Web-UI → Add Engine | Nein, optional, kommt erst später falls überhaupt. |
| Machine-Credentials | Nur für Multi-Host (LAPI hier, Agent woanders) | `cscli lapi register` | Nein, bei Single-Host irrelevant. |

Im Caddyfile-Snippet steht `api_key {env.CROWDSEC_API_KEY}` — Caddy holt den Wert beim Start aus `/etc/caddy/env`. Da rein gehört der **Bouncer-Key** aus dem nächsten Befehl, nichts anderes.

### Bouncer-Key generieren (den braucht Caddy gleich)

```bash
cscli bouncers add caddy-bouncer
# → Notiere dir den ausgegebenen API-Key. Er wird nur einmal angezeigt.
```

API-Key in `/etc/caddy/env` schreiben:

```bash
echo "CROWDSEC_API_KEY=DEIN_KEY_HIER" > /etc/caddy/env
chmod 600 /etc/caddy/env
chown caddy:caddy /etc/caddy/env
```

Detection-Collections installieren:

```bash
cscli collections install crowdsecurity/http-cve
cscli collections install crowdsecurity/base-http-scenarios
cscli collections install crowdsecurity/sshd   # falls SSH von außen erreichbar ist
```

CrowdSec soll Caddy-Access-Logs lesen. Datei `/etc/crowdsec/acquis.d/caddy.yaml` anlegen:

```yaml
filenames:
  - /var/log/caddy/access.log
labels:
  type: caddy
```

CrowdSec neustarten:

```bash
systemctl restart crowdsec
cscli decisions list
# Du solltest direkt ein paar tausend Einträge aus der Community-Blocklist sehen.
```

### Brauchst du einen CrowdSec-Account?

**Nein.** CrowdSec funktioniert vollständig ohne Account. Das, was du oben gesehen hast — Tausende Einträge aus der Community-Blocklist (CAPI = Central API) — kommt automatisch und kostenlos, ohne dass du dich irgendwo registrierst. Die Engine pullt die Liste alle paar Stunden, dein Bouncer wendet sie an. Fertig.

Was ein Account (kostenlos auf [app.crowdsec.net](https://app.crowdsec.net)) zusätzlich bringt:

- Web-Dashboard mit Live-Decisions, Top-Angreifer, Geo-Map
- Mehrere Engines bündeln (z.B. später Server bei einem Kollegen)
- Eigene Blocklisten teilen oder von Dritten subscriben (Premium-Listen)
- Push-Notifications bei Großangriffen

Anlegen kannst du das **jederzeit später** ohne dass irgendwas an deinem Setup zerbricht — die Engine arbeitet weiter wie bisher, du bindest sie nur dazu:

```bash
# Wann immer du den Account magst:
cscli console enroll DEIN_ENGINE_TOKEN
# Token aus app.crowdsec.net → Add Engine
```

Für den Erstaufschlag also: Account ignorieren, später bei Bedarf nachrüsten.

---

## Schritt 7: Caddyfile

Das ist die zentrale Konfiguration. `/etc/caddy/Caddyfile`:

```caddy
{
    # Handler-Reihenfolge: CrowdSec MUSS vor reverse_proxy laufen,
    # sonst greift der Bouncer nicht
    order crowdsec before reverse_proxy

    # Globaler CrowdSec-Block — Bouncer redet mit lokaler LAPI
    crowdsec {
        api_url http://127.0.0.1:8080
        api_key {env.CROWDSEC_API_KEY}
        ticker_interval 15s
        # Streaming ist seit Plugin-Version >0.7 Default-on.
        # Nur deaktivieren falls du LAPI manuell pollen willst:
        #   disable_streaming
    }

    # Runtime-Logging (TLS, ACME, Layer4 — KEINE HTTP-Access-Logs!)
    log {
        output file /var/log/caddy/runtime.log {
            roll_size 50MiB
            roll_keep 5
        }
        format json
    }

    # ACME-Mailadresse für Let's Encrypt
    email du@deine-domain.de

    # Admin-API nur lokal
    admin localhost:2019
}

# Beispiel-Service 1: Nextcloud
nextcloud.deine-domain.de {
    # PFLICHT: Per-Site-Log für CrowdSec-HTTP-Detection
    log {
        output file /var/log/caddy/access.log {
            roll_size 50MiB
            roll_keep 5
        }
        format json
    }

    # CrowdSec-Bouncer aktivieren
    crowdsec

    # Port hängt von DEINEM Setup ab — siehe Hinweis unter dem Block.
    # Apache-Variant: 80 · AIO: 11000 · Reverse-Proxy-Image: oft 80 oder 8080
    reverse_proxy 192.168.1.50:80
}

# Beispiel-Service 2: Vaultwarden
vaultwarden.deine-domain.de {
    log {
        output file /var/log/caddy/access.log
        format json
    }
    crowdsec
    # Vaultwarden-Default ist :80, viele Compose-Setups mappen aber :8080.
    # Schau in dein docker-compose.yml.
    reverse_proxy 192.168.1.51:80
}

# Beispiel-Service 3: Jellyfin (Streaming — siehe „Spezialfall: Jellyfin" unten)
jellyfin.deine-domain.de {
    log {
        output file /var/log/caddy/access.log
        format json
    }
    crowdsec

    # X-Forwarded-Proto und X-Forwarded-Host setzt Caddy automatisch.
    # Nur X-Real-IP brauchen wir explizit, damit Jellyfin echte Client-IPs loggt.
    reverse_proxy 192.168.1.52:8096 {
        header_up X-Real-IP {remote_host}
    }
}
```

> ⚠ **Wichtigster Hinweis der ganzen Anleitung:** Jeder Site-Block braucht den eigenen `log {}` Block. Der globale Logger schreibt **keine** `http.log.access`-Einträge — er erfasst nur Runtime-Events (TLS-Handshakes, ACME, Layer4). CrowdSec liest aber ausschließlich `http.log.access`. Ohne Per-Site-Log siehst du in `cscli alerts list` einfach nichts, egal wie viel Angriff reinkommt. Das ist der eine Stolperstein, den fast jeder beim ersten Setup macht.

> 📌 **Backend-Ports sind setup-spezifisch:** Die `reverse_proxy <host>:<port>` Werte oben sind Beispiele. Der echte Port kommt aus deinem Backend-Container/-Service:
> - **Nextcloud** Apache-Image: `:80` · NextcloudAIO: `:11000` (HTTP) oder `:11443` (HTTPS) · Custom-Compose: laut deinem `docker-compose.yml`.
> - **Vaultwarden**: Default-`ROCKET_PORT=80`, viele Compose-Setups exposen aber `8080`.
> - **Jellyfin**: Default `:8096`.
> - **Generischer Test:** Vom Caddy-Host aus `curl -v http://<backend-ip>:<port>/` — antwortet was, ist der Port richtig. „Connection refused" → falscher Port oder Service nicht da.
> Falscher Port führt typischerweise zu `HTTP 502 Bad Gateway` (siehe Stolperstein 10).

Validieren und Service starten:

```bash
# Validate (env-Datei sourcen, sonst sieht caddy validate {env.CROWDSEC_API_KEY} als leer):
set -a; . /etc/caddy/env; set +a
caddy validate --config /etc/caddy/Caddyfile

# Service starten — systemd lädt /etc/caddy/env automatisch:
systemctl daemon-reload
systemctl enable --now caddy
journalctl -u caddy -f
```

> 💡 **Wenn `caddy validate` „crowdsec API key must not be empty" sagt, obwohl der Key in `/etc/caddy/env` steht:** `caddy validate` läuft ohne systemd-Kontext und lädt die env-Datei nicht. Entweder vorher sourcen (siehe oben) oder den `validate`-Schritt überspringen und direkt `systemctl enable --now caddy` machen — systemd liest `EnvironmentFile=` aus der Service-Unit und der Key ist beim echten Start da.

Die ersten ACME-Challenges laufen 30–90 Sekunden nach dem Start. Wenn du `tls_handshake_complete` siehst, läuft TLS.

---

## Schritt 8: Verifizieren

```bash
# Services laufen?
systemctl status caddy crowdsec

# HTTPS antwortet?
curl -I https://nextcloud.deine-domain.de

# CrowdSec sieht Caddy-Logs?
cscli metrics | grep caddy
# Du solltest Acquis-Zeilen mit Source "file:/var/log/caddy/access.log" sehen

# Welche Decisions sind aktiv?
cscli decisions list

# Wie viele Alerts hat CrowdSec generiert?
cscli alerts list
```

Wenn `cscli metrics | grep caddy` leer ist, fehlt der Per-Site-`log`-Block (siehe Hinweis oben).

---

## Spezialfall: Jellyfin

Jellyfin hinter Caddy ist ein häufiger Fall und funktioniert ohne große Akrobatik — aber es gibt ein paar Punkte, die du wissen solltest, sonst läufst du in Streaming-Stutter oder kaputte Client-IPs.

### Caddyfile-Block

Den minimalen Block hast du oben schon gesehen. Hier die kommentierte Variante:

```caddy
jellyfin.deine-domain.de {
    log {
        output file /var/log/caddy/access.log
        format json
    }
    crowdsec

    reverse_proxy 192.168.1.52:8096 {
        # Echte Client-IP weiterreichen — Jellyfin sieht sonst nur 127.0.0.1.
        # X-Forwarded-Proto und X-Forwarded-Host setzt Caddy schon automatisch
        # in jedem reverse_proxy — die brauchen wir NICHT explizit (das gibt
        # nur „Unnecessary header_up"-Warnings beim Start).
        header_up X-Real-IP {remote_host}

        # WebSockets brauchen keine extra Direktive — Caddy erkennt das Upgrade automatisch.
        # Buffering ist bei Caddy 2 für reverse_proxy default off — gut für Streaming.
    }

    # Optional: Security-Header (machen Jellyfin nicht kaputt)
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        # KEIN X-Frame-Options DENY — Jellyfin nutzt Iframes für manche Funktionen
    }
}
```

### Jellyfin selbst muss konfiguriert werden

In **Jellyfin → Dashboard → Networking** musst du Caddy als „Known Proxy" eintragen, sonst loggt Jellyfin alle Requests mit Caddy-IP statt der echten Client-IP — was wiederum CrowdSec falsche Detection-Daten liefert (alle Angriffe sehen aus, als kämen sie von Caddys IP).

| Feld | Wert |
|------|------|
| **Known proxies** | IP des Caddy-Containers (z.B. `192.168.1.10`) |
| **Trust X-Forwarded-For** | aktivieren |
| **Public HTTPS port** | 443 |
| **Secure connection mode** | „Handled by reverse proxy" |

Nach Speichern: Jellyfin neustarten.

### Was beim Streaming wichtig ist

- **Direct Play** (Client kann das Format) → Caddy reicht den Stream einfach durch, keine Sonderkonfig nötig.
- **Transcoding** → Jellyfin generiert HLS-Segmente. Diese landen als kurze HTTP-Range-Requests bei Caddy. Caddy macht das per default richtig. Falls du **stutter** siehst: prüfe ob CrowdSec aggressive Rate-Limit-Szenarien hat — viele kurze Range-Requests können wie Scraping aussehen. Lösung: eigene IP whitelisten oder das Szenario `crowdsecurity/http-probing` deaktivieren.
- **Live-TV / DLNA** → läuft nicht über Reverse Proxy. DLNA ist Multicast-Protokoll, das gehört in dein LAN, nicht ins Internet.
- **WebSocket** (Sync-Funktionen, Now-Playing-Updates) → läuft transparent in Caddy 2, kein `header_up Connection upgrade` nötig wie bei nginx.
- **HTTP/2 + HTTP/3** sind aktiviert per default und Jellyfin verträgt beide.

### Große Uploads (Plugin, Bilder)

Caddy hat **kein** default-Body-Limit — anders als nginx. Du kannst also auch 4-GB-Plugin-Uploads durchreichen, ohne `client_max_body_size` zu setzen. Falls du ein Limit willst, machst du das via `request_body { max_size 100MB }` im Site-Block.

### Test

```bash
# Zertifikat ok?
curl -I https://jellyfin.deine-domain.de

# Echte IP kommt durch?
# In Jellyfin Dashboard → Logs → Activity → checken ob deine echte IP erscheint, nicht 192.168.x.10

# WebSocket-Upgrade funktioniert?
# Im Browser DevTools → Network → ws-Filter → Verbindung sollte „101 Switching Protocols" zeigen
```

### Häufiger Fehler: 502 nach Login

Symptom: Login-Seite lädt, nach Klick auf „Sign In" → 502.
Ursache: Jellyfin sendet einen Set-Cookie mit `Secure`-Flag, weil es per X-Forwarded-Proto „https" sieht — aber der Login-Request ging an Jellyfins HTTP-Port. Lösung: in Jellyfin „Secure connection mode" auf „Handled by reverse proxy" setzen (siehe Tabelle oben). Das ist der einzige Knackpunkt, an dem viele bei Jellyfin+Caddy hängen.

---

## Optional: Layer-4 (TCP/UDP) für RustDesk

Falls du einen RustDesk-Server selbst hostest — Caddy kann das auch:

```caddy
{
    layer4 {
        :21115 {
            route {
                proxy tcp/192.168.1.60:21115
            }
        }
        :21116 {
            route {
                proxy tcp/192.168.1.60:21116
            }
        }
        # UDP-Variante:
        udp/:21116 {
            route {
                proxy udp/192.168.1.60:21116
            }
        }
    }
}
```

Der Layer-4-Block kommt **außerhalb** der HTTP-Site-Blöcke, ins globale `{}`.

---

## Pflege im Alltag

Caddy + CrowdSec sind beide pflegeleicht, aber **nicht** „einmal aufsetzen und vergessen". Hier der realistische Aufwand.

### Monatliche Routine (5–10 Minuten)

```bash
# CrowdSec-Hub aktualisieren — neue Detection-Szenarien holen
cscli hub update
cscli hub upgrade
systemctl reload crowdsec

# System-Updates
apt update && apt upgrade -y

# Status checken
systemctl status caddy crowdsec
cscli metrics

# Aktuelle Bedrohungslage
cscli alerts list --since 720h | head -30
```

### Caddy aktualisieren

Da wir Custom-Build nutzen, ziehen wir Caddy-Updates **nicht** über apt. Etwa alle 3–6 Monate, oder wenn du eine Caddy-Security-Notice siehst (ich abonniere dafür den GitHub-Releases-Feed):

```bash
cd /tmp
xcaddy build \
  --with github.com/mholt/caddy-l4 \
  --with github.com/hslatman/caddy-crowdsec-bouncer/http \
  --with github.com/hslatman/caddy-crowdsec-bouncer/layer4 \
  --with github.com/hslatman/caddy-crowdsec-bouncer/appsec \
  --with github.com/hslatman/caddy-crowdsec-bouncer/crowdsec

# Alte Binary sichern, dann tauschen
cp /usr/bin/caddy /usr/bin/caddy.bak
mv ./caddy /usr/bin/caddy

# Validieren BEVOR du reloads
caddy validate --config /etc/caddy/Caddyfile
caddy version

systemctl reload caddy
journalctl -u caddy -n 30 --no-pager

# Falls was bricht: instant rollback
mv /usr/bin/caddy.bak /usr/bin/caddy
systemctl reload caddy
```

> Tipp: `xcaddy build` ohne Versions-Pin nimmt automatisch latest. Wenn du eine bestimmte Caddy-Version willst: `xcaddy build v2.10.0 --with ...`.

### CrowdSec aktualisieren

CrowdSec ist normales apt-Paket:

```bash
apt update && apt upgrade crowdsec
systemctl restart crowdsec

# Hub-Inhalte (Szenarien, Parser) separat:
cscli hub update
cscli hub upgrade
systemctl reload crowdsec
```

### Neuen Service hinzufügen

Der häufigste Pflege-Vorgang. Workflow:

1. Block in `/etc/caddy/Caddyfile` ergänzen — **mit Per-Site-`log {}`-Block, immer**
2. Validieren: `caddy validate --config /etc/caddy/Caddyfile`
3. Reload: `systemctl reload caddy`
4. ACME zieht das Zertifikat innerhalb 1–2 Min automatisch
5. Test: `curl -I https://neuer-service.deine-domain.de`

Falls's nicht klappt: `journalctl -u caddy -f` während Reload beobachten — Tippfehler im Caddyfile fallen sofort auf.

### Zertifikats-Status prüfen

Caddy renewt automatisch ~30 Tage vor Ablauf. Manuelles Check:

```bash
# Wo liegen die Zerts?
ls -la /var/lib/caddy/.local/share/caddy/certificates/

# Ablaufdatum eines Zerts
echo | openssl s_client -servername nextcloud.deine-domain.de \
  -connect nextcloud.deine-domain.de:443 2>/dev/null \
  | openssl x509 -noout -dates
```

### Logs rotieren

Caddy rotiert Access-Logs selbst (`roll_size 50MiB`, `roll_keep 5` aus dem Caddyfile — das hatten wir oben gesetzt). CrowdSec-Logs liegen in `/var/log/crowdsec.log` und werden via `logrotate` rotiert (kommt mit dem Paket).

```bash
ls -lh /var/log/caddy/
ls -lh /var/log/crowdsec.log*
```

Wenn du irgendwann mehr Traffic hast, kannst du `roll_size` und `roll_keep` im Caddyfile hochziehen.

### Bans im Container sehen und auflösen

Das ist der häufigste Pflege-Vorgang nach „neuer Service hinzufügen". Alles passiert über `cscli` direkt im Container, keine Web-UI nötig.

#### Wer ist gerade gesperrt?

```bash
# Alle aktiven Bans (mit Quelle, Grund, Ablaufzeit)
cscli decisions list

# Nur eine bestimmte IP suchen
cscli decisions list --ip 1.2.3.4

# Alle Bans aus einer Region/Reason
cscli decisions list --scope Ip --type ban
```

Die Ausgabe zeigt: ID, Source (CAPI = Community-Liste, oder Name deines Szenarios), Scope (meist „Ip"), Value (die IP), Reason, Action („ban"), Country, AS, Events count, Expiration.

#### Eine konkrete IP entbannen

```bash
# Per IP — der häufigste Fall
cscli decisions delete --ip 1.2.3.4

# Per Decision-ID (aus „cscli decisions list")
cscli decisions delete --id 12345

# Alle Bans aus einer Quelle löschen (z.B. nach Fehlkonfiguration eines Szenarios)
cscli decisions delete --origin crowdsecurity/http-probing
```

#### Ich bin selbst ausgesperrt — was tun?

Erste Hilfe vom Caddy-Container aus (du brauchst SSH/Console-Zugang zur Box, **nicht** zur Web-UI):

```bash
# Notbremse: deine eigene Public-IP entbannen
cscli decisions delete --ip $(curl -s ifconfig.me)

# Ganz harte Notbremse: ALLE Bans löschen (nur als Notfall, du verlierst auch CAPI-Schutz für ~1h
# bis die Engine die Community-Liste wieder zieht)
cscli decisions delete --all
```

Falls du gar keinen Zugang mehr zur Box hast (z.B. SSH läuft auch über Caddy/CrowdSec) — dann brauchst du physischen oder Hypervisor-Konsolen-Zugang. Deshalb: SSH **nie** ausschließlich über CrowdSec-überwachte Pfade laufen lassen, sondern entweder LAN-only halten oder via VPN-Bypass — siehe Stolperstein 2.

#### IP dauerhaft whitelisten (überlebt Re-Detection)

`cscli decisions delete` ist nur für die **aktuelle** Decision. Wenn die IP wieder ein Szenario triggert, kommt der Ban zurück. Für persistente Whitelists schreibst du eine YAML-Datei:

`/etc/crowdsec/parsers/s02-enrich/my-whitelist.yaml`:

```yaml
name: custom/my-whitelist
description: "Whitelist meiner LAN- und VPN-Clients"
whitelist:
  reason: "Trusted networks"
  ip:
    - "203.0.113.42"        # meine Büro-IP
  cidr:
    - "192.168.1.0/24"      # LAN
    - "10.8.0.0/24"         # WireGuard
```

Dann:

```bash
systemctl reload crowdsec
```

Diese Whitelist greift **vor** der Detection — die IPs erzeugen also gar keine Alerts mehr, nicht nur „kein Ban trotz Alert".

#### Alarmhistorie nachvollziehen

Was hat CrowdSec überhaupt erkannt, bevor es einen Ban gesetzt hat?

```bash
# Letzte 20 Alerts
cscli alerts list --limit 20

# Letzte 24h
cscli alerts list --since 24h

# Detail eines bestimmten Alerts (Events, Quelle, Szenario)
cscli alerts inspect 4711

# Nur eigene Alerts (ohne CAPI-Community-Liste)
cscli alerts list --source crowdsec
```

#### Bouncer-Status prüfen

Damit Bans im Caddy auch ankommen, muss der Bouncer mit der LAPI reden:

```bash
# Sind Bouncer registriert und „connected"?
cscli bouncers list

# In Caddys Logs nach CrowdSec-Heartbeats suchen
journalctl -u caddy -n 50 | grep -i crowdsec
```

Ein gesunder Bouncer zeigt einen kürzlichen `last_pull` Timestamp (idealerweise < `ticker_interval` aus dem Caddyfile, also unter 15s alt).

### Backup

Was du wirklich sichern musst — meist unter 20 MB:

```bash
tar czf caddy-backup-$(date +%F).tar.gz \
  /etc/caddy \
  /etc/crowdsec \
  /etc/systemd/system/caddy.service \
  /var/lib/caddy/.local/share/caddy
```

Damit bist du auf einer leeren Box innerhalb von 30 Min wieder live (Caddy-Binary baust du dann frisch via xcaddy — die ist nicht im Backup, das spart Platz und hält das Backup version-unabhängig).

### Monitoring (optional, aber empfohlen)

- **CrowdSec-Console** (kostenlos, web): [app.crowdsec.net](https://app.crowdsec.net) — zeigt Live-Decisions, Top-Angreifer, Geo-Map. Engine via `cscli console enroll <token>` verbinden.
- **Uptime-Monitoring:** Wenn du Uptime-Kuma o.ä. hast, einen HTTP-Check auf einen Lightweight-Endpunkt + Webhook-Notify bei Ausfall.
- **Disk:** CrowdSec-DB wächst langsam, aber stetig. `du -sh /var/lib/crowdsec/` einmal im Quartal prüfen.

### Wenn was schiefgeht

| Symptom | Erste Befehle |
|---------|---------------|
| Caddy startet nicht | `caddy validate --config /etc/caddy/Caddyfile && journalctl -u caddy -n 80` |
| 502 Bad Gateway | Backend-Service prüfen, dann `journalctl -u caddy -f` während Request |
| Zertifikat abgelaufen | `journalctl -u caddy \| grep -iE "renewal\|acme"` |
| CrowdSec sperrt zu aggressiv | `cscli alerts list --since 1h` und Whitelist setzen |
| Eigene IP gesperrt | `cscli decisions delete --ip $(curl -s ifconfig.me)` |
| RAM hoch | `cscli metrics` — falls LAPI viele Verbindungen hat, `ticker_interval` im Caddyfile hochsetzen |
| CrowdSec liest keine Logs | `tail /var/log/crowdsec.log \| grep caddy` und Per-Site-`log` prüfen |

### Realistischer Aufwand

| Frequenz | Was | Zeit |
|----------|-----|------|
| Monatlich | Hub-Update, apt upgrade, Status-Sichtkontrolle | 5–10 Min |
| Alle 3–6 Monate | Caddy neu bauen + tauschen | 10–15 Min |
| Bei jedem neuen Service | Caddyfile-Block + Reload + Test | 5 Min |
| Bei Vorfall | Ban prüfen, ggf. whitelisten | 2 Min |
| Jährlich | Go-Update, Backup-Restore-Übung | 30 Min |

Das ist es. Wer Zoraxy mit seiner Web-UI gewohnt war, wird die fehlende GUI vielleicht erst vermissen — dafür ist das System im Code (Caddyfile) deklariert, versionierbar in Git, und reproduzierbar in Minuten neu aufgebaut.

---

## Stolpersteine aus der Praxis

### 1. Per-Site `log` ist Pflicht

Bereits oben ausführlich. Wenn nur eines hängenbleibt, dann das.

### 2. IP-Restriktionen plus CrowdSec gleich Ban-Kaskade

Wenn du eine Site mit IP-Allowlist baust (z.B. „nur aus dem LAN") und dein VPN-User triggert ein paar 403er, sperrt CrowdSec die VPN-IP nach kurzer Zeit als Brute-Force. Lieber Service-eigene Auth nutzen statt Caddy-IP-Restriktion auf CrowdSec-überwachten Sites.

### 3. Zertifikate kommen nicht

Checkliste:

- DNS-A-Record zeigt wirklich auf deine öffentliche IP?
- Port 80 (für ACME-HTTP-01) und 443 von außen erreichbar?
- Logs: `journalctl -u caddy | grep -i acme`

### 4. CrowdSec sieht nichts

```bash
tail -f /var/log/crowdsec.log | grep caddy
# Bleibt das stumm → acquis.d/caddy.yaml prüfen, CrowdSec restarten.
```

### 5. Bouncer authentifiziert nicht

```bash
journalctl -u caddy | grep -i crowdsec
# "unauthorized" → Key in /etc/caddy/env passt nicht zu cscli bouncers list
```

Lösung: Neuen Bouncer-Key generieren und in `/etc/caddy/env` aktualisieren.

### 6. „crowdsec API key must not be empty" — kompletter Wiedereinstieg

Wenn du bei `systemctl start caddy` (oder schon bei `caddy validate`) genau das hier siehst:

```
Error: loading crowdsec app module: crowdsec: invalid configuration:
crowdsec API key must not be empty
```

…dann liest du jetzt am richtigen Platz. Mach die folgenden Schritte in genau dieser Reihenfolge — danach läuft Caddy.

**Schritt 6.1 — Bouncer-Key generieren (falls noch nicht passiert):**

```bash
cscli bouncers add caddy-bouncer
```

Der Output zeigt einen langen Hex-Key. **Kopiere ihn jetzt** — er wird nur dieses eine Mal angezeigt.

**Schritt 6.2 — Echten Key in `/etc/caddy/env` eintragen:**

```bash
# Den Platzhalter DEIN_KEY_HIER durch deinen echten Key ersetzen:
echo "CROWDSEC_API_KEY=HIER_DEN_KEY_AUS_6.1_EINFUEGEN" > /etc/caddy/env
chmod 600 /etc/caddy/env
chown caddy:caddy /etc/caddy/env

# Verify:
cat /etc/caddy/env
# sollte CROWDSEC_API_KEY=<langer Hex-String> zeigen, nicht DEIN_KEY_HIER
```

**Schritt 6.3 — Permissions auf den Log-Ordner reparieren** (siehe auch Stolperstein 7):

```bash
chown -R caddy:caddy /var/log/caddy
chown -R caddy:caddy /var/lib/caddy
```

**Schritt 6.4 — Optionaler Cleanup im Caddyfile:**

In deinem Jellyfin-Block hattest du noch zwei überflüssige Zeilen:

```caddy
header_up X-Forwarded-Proto {scheme}    # → diese Zeile löschen
header_up X-Forwarded-Host {host}       # → diese Zeile löschen
```

Die produzieren beim Start nur „Unnecessary header_up"-Warnings. Caddy v2 setzt beide Header schon automatisch in jedem `reverse_proxy`. Behalte nur `header_up X-Real-IP {remote_host}`. (Optional — Caddy startet auch ohne diese Korrektur.)

**Schritt 6.5 — Optionaler Format-Cleanup:**

```bash
caddy fmt --overwrite /etc/caddy/Caddyfile
```

Räumt die „Caddyfile input is not formatted"-Warnung weg.

**Schritt 6.6 — Jetzt starten:**

```bash
# Service direkt über systemd starten — DAS ist der echte Test.
# systemd lädt /etc/caddy/env automatisch (siehe EnvironmentFile= in der Unit aus Schritt 5).
systemctl daemon-reload
systemctl enable --now caddy
journalctl -u caddy -f
```

> ⚠ **`caddy validate` ist hier irreführend!** Der Befehl läuft ohne systemd-Kontext und lädt `/etc/caddy/env` deshalb **nicht**. Wenn du `caddy validate` machst, siehst du immer „crowdsec API key must not be empty" — das ist **kein** echter Fehler, der Key in deiner env-Datei ist sauber, nur `validate` ist blind dafür. Entweder den `validate`-Schritt überspringen (siehe oben) oder vorher env sourcen: `set -a; . /etc/caddy/env; set +a; caddy validate ...`

Erwarte: keine Errors im `journalctl`-Stream, ACME zieht innerhalb von 30–90 Sekunden die Zertifikate für die Site-Blöcke aus deinem Caddyfile. Wenn du `tls_handshake_complete` Logzeilen siehst, läuft TLS.

**Schritt 6.7 — Verifizieren:** Geh zu **Schritt 8** im Hauptguide. Dort stehen die Test-Befehle (`curl -I https://...` für jeden Service, `cscli metrics | grep caddy`, `cscli decisions list`).

Wenn 6.6 sauber durchgeht, bist du fertig. Falls nicht: schick die letzten 30 Zeilen `journalctl -u caddy -n 30 --no-pager`.

### 7. „permission denied" auf `/var/log/caddy/runtime.log`

Caddy will beim Start sein Logfile öffnen und schlägt fehl mit:

```
open /var/log/caddy/runtime.log: permission denied
```

Bedeutet: Der `caddy`-Systemuser hat keine Schreibrechte auf den Log-Ordner. Typisch wenn der Ordner als root angelegt wurde, der `caddy`-User aber erst später.

**Fix:**

```bash
chown -R caddy:caddy /var/log/caddy
chown -R caddy:caddy /var/lib/caddy
systemctl start caddy
```

(Das ist Schritt 6.3 in Stolperstein 6 oben — wenn du den durchläufst, ist's da schon mit drin.)

### 8. „Caddyfile input is not formatted" Warnung

```
WARN  Caddyfile input is not formatted; run 'caddy fmt --overwrite' to fix inconsistencies
```

Rein kosmetisch — Tabs vs. Spaces oder kleine Unstimmigkeiten in der Einrückung. Caddy läuft trotzdem. Einmaliger Befehl räumt's auf:

```bash
caddy fmt --overwrite /etc/caddy/Caddyfile
```

### 9. „failed to sufficiently increase receive buffer size" (HTTP/3-UDP-Buffer)

Im journal beim Caddy-Start:

```
failed to sufficiently increase receive buffer size
(was: 208 kiB, wanted: 7168 kiB, got: 416 kiB)
```

Performance-Warnung für HTTP/3 (QUIC), **kein** Funktionsfehler. HTTP/2 läuft normal weiter. HTTP/3 funktioniert auch — nur mit kleinerem UDP-Empfangspuffer.

**Standard-Fix (Bare-Metal, KVM-VM):**

```bash
echo "net.core.rmem_max=7500000" > /etc/sysctl.d/99-quic.conf
echo "net.core.wmem_max=7500000" >> /etc/sysctl.d/99-quic.conf
sysctl --system
systemctl restart caddy
```

**Wenn du in einem LXC-Container läufst** (Proxmox, Incus, …): `sysctl --system` schlägt fehl mit `Operation not permitted` auf `net.core.*` — der Container hat kein eigenes Net-Namespace mit Schreibrecht auf diese Keys. **Lösung:** Setze die Werte stattdessen auf dem **Host** (z.B. dem Proxmox-Host) in `/etc/sysctl.d/99-quic.conf`. Sie wirken automatisch auf alle Container. Im Container selbst nichts tun.

Wenn dich die Warnung in keinem Setup stört: einfach ignorieren, Caddy läuft auch so.

### 10. 502 Bad Gateway

Caddy ist sauber gestartet, TLS-Cert da, einzelne Backends antworten — aber andere reagieren mit `HTTP/2 502`. Drei Ursachen, in der Reihenfolge der Häufigkeit:

#### Ursache 1: Falscher Backend-Port im Caddyfile

Klassiker. Jedes Backend-Image macht's anders. Schnell-Diagnose vom Caddy-Host aus:

```bash
curl -v http://<backend-ip>:<port>/
```

- Antwort kommt → Port ist richtig, Ursache liegt woanders (siehe 2 oder 3).
- `Connection refused` → Service lauscht nicht auf diesem Port. Schau in dein `docker-compose.yml` / die App-Doku, korrigiere `reverse_proxy <ip>:<port>` im Caddyfile, `systemctl reload caddy`.
- `Timeout` → Firewall blockt zwischen Caddy und Backend, oder Service ist down.

Häufige Defaults (nicht erschöpfend):
- Nextcloud Apache: `:80` · NextcloudAIO: `:11000`/`:11443`
- Vaultwarden: `:80` (Default) — manche Compose-Setups: `:8080`
- Jellyfin: `:8096`
- GitLab: `:80` (Container) oder `:8080` (omnibus mit Reverse-Proxy-Mode)
- Paperless-ngx: `:8000`

#### Ursache 2: Backend lehnt den neuen Proxy ab (Migrations-Fall)

Wenn du gerade von einem alten Reverse-Proxy migriert hast und die Bestands-Apps (Nextcloud, GitLab, WordPress mit Reverse-Proxy-Plugins) plötzlich 502 werfen: Die haben sich oft die **IP des alten Reverse Proxys** als „trusted Proxy" oder „known Host" gemerkt. Der neue Caddy hat eine andere IP, die App ignoriert ihn (oder Forwarded-Header werden nicht akzeptiert).

**Zwei Wege:**

**A — App-Konfig anpassen (sauberer Weg):**

In jeder Backend-App die neue Caddy-IP als trusted Proxy eintragen. Beispiele:

- **Nextcloud** (`config/config.php`):
  ```php
  'trusted_proxies' => ['10.x.x.x'],
  'overwriteprotocol' => 'https',
  'overwritehost' => 'cloud.deine-domain.de',
  ```
- **GitLab** (`/etc/gitlab/gitlab.rb`): `gitlab_rails['trusted_proxies'] = ['10.x.x.x']`
- **WordPress** mit Reverse-Proxy-Plugins: Plugin-Config prüfen
- **Vaultwarden** ist meist unkritisch — prüfe nur die `DOMAIN`-Env-Var

Dann jeweils Backend-Service neustarten.

**B — IP-Vererbung via MAC-Swap (pragmatisch, wenn DHCP):**

Den alten Reverse Proxy stilllegen und dem neuen die **MAC-Adresse** des alten zuweisen. Der neue Proxy bekommt beim DHCP-Lease die alte IP. Backends sehen weiter „die gleiche Proxy-IP wie immer" — null Backend-Konfig-Anpassung nötig.

```bash
# Auf dem Hypervisor-Host (Beispiel Proxmox), neuer LXC:
pct set <CTID> -net0 name=eth0,bridge=vmbr0,hwaddr=BC:24:11:XX:XX:XX
# (alte MAC-Adresse des alten Proxy einsetzen)
pct stop <CTID> && pct start <CTID>

# Bei VMs:
qm set <VMID> -net0 model=virtio,macaddr=BC:24:11:XX:XX:XX,bridge=vmbr0
```

Vorteil: keine einzige Backend-App muss angefasst werden. Nachteil: du erbst die History des alten Proxys (z.B. CrowdSec-Decisions die auf diese IP zielten greifen jetzt am neuen Proxy — meist egal, manchmal überraschend).

Welcher Weg richtig ist, hängt davon ab wie viele Backends du hast und wie sehr du Wegwerf-Konfig magst. **A** ist sauberer und versionierbar; **B** ist 30 Sekunden pro Migration.

#### Ursache 3: Backend-Service down

Wenn `curl -v` von der Caddy-Box auf den Backend-Port `Connection refused` liefert und der Port stimmt: prüfe ob der Service überhaupt läuft.

```bash
# Auf dem Backend-Host:
systemctl status nextcloud   # oder docker compose ps
```

Banal, aber leicht zu übersehen wenn man nur in den Caddy-Logs gräbt.

### 11. Performance-Sorgen

CrowdSec hat eine lokale SQLite-DB mit aktuell ~30k Einträgen. Bei jedem Request fragt der Bouncer per Streaming-Update lokal — keine Latenz. Solltest du auf einem RPi laufen, halte `ticker_interval` auf 15s oder mehr.

### 12. Reload haengt — CrowdSec Streaming-Bouncer Bug

**Symptom:** `systemctl reload caddy` haengt unbegrenzt im Timeout. `GET /config/...` Admin-API antwortet nicht (8s Timeout, 0 Bytes), aber andere Endpoints (`/pki/ca/local`, `/reverse_proxy/upstreams`, `/metrics`) sind sub-Millisekunde-schnell. Production-HTTPS-Traffic ist **nicht** beeintraechtigt — nur die Reload-Pipeline und Voll-Config-Reads.

**Diagnose-Pfad:**

```bash
# Endpoint-Selektivitaet pruefen — nur /config/* sollte haengen
for p in /config/admin /pki/ca/local /reverse_proxy/upstreams /metrics; do
  printf "%-30s " "$p"
  curl -s -m 5 -o /dev/null -w "TIME=%{time_total}s HTTP=%{http_code}\n" "localhost:2019$p"
done

# Goroutine-Dump waehrend Hang ziehen
curl -s localhost:2019/debug/pprof/goroutine?debug=2 > /tmp/dump.txt
grep -c "caddy-crowdsec-bouncer/http" /tmp/dump.txt   # >100 Stacks = Smoking Gun
```

**Root-Cause:** Der Streaming-Bouncer (Default seit `caddy-crowdsec-bouncer` >0.7) haelt eine permanente HTTP-Connection zur lokalen LAPI offen. Beim Graceful-Reload muss diese Connection geschlossen werden — das haengt im Admin-Server-Lock und blockiert alle `/config/...`-Endpoints, weil die den gleichen Lock zum Marshalen brauchen. Andere Endpoints haben separate Code-Pfade. Upstream-Issue: [hslatman/caddy-crowdsec-bouncer#61](https://github.com/hslatman/caddy-crowdsec-bouncer/issues/61) (offen seit 2024-12).

**Fix:** `disable_streaming` im globalen `crowdsec { ... }` Block ergaenzen:

```caddy
crowdsec {
    api_url http://127.0.0.1:8080
    api_key {env.CROWDSEC_API_KEY}
    ticker_interval 15s
    disable_streaming
}
```

**Wichtig:** Danach `systemctl restart caddy`, **nicht** `reload` — der reload haengt ja, das war der Bug. Henne-Ei: ohne `disable_streaming` greift der neue State nicht, ohne Restart kein neuer State.

**Verifikation:**

```bash
systemctl restart caddy
systemctl reload caddy        # muss jetzt in <100ms durchgehen
curl -s -m 5 localhost:2019/config/ | wc -c    # muss ~10000+ Bytes liefern
```

**Trade-off:** Bouncer arbeitet im Live-Mode statt Streaming — pro HTTP-Request ein Lookup zur LAPI (~1-5 ms Loopback-Latenz auf 127.0.0.1). Auf Heim-Setups vernachlaessigbar. Bei sehr hohem Traffic (>100 req/s) und grosser Decision-DB neu evaluieren. Ban-Apply-Latenz bleibt vergleichbar (eher etwas besser, weil per-Request frisch gecheckt statt vom Cache mit Sync-Lag).

**Wann betroffen:** Caddy 2.11.x mit `caddy-crowdsec-bouncer >0.7` (Default-Streaming). Verschaerft sich mit `caddy-l4` (langlebige TCP/UDP-Connections wie RustDesk-Relay), aber Streaming alleine reicht zur Reproduktion. Vorfall lab02 CT 122 am 2026-05-06: 8s Timeout auf `/config/*`, ueber Goroutine-Dump als Streaming-Bug bestaetigt.

---

## Cheatsheet

| Aufgabe | Befehl |
|---------|--------|
| Config validieren | `caddy validate --config /etc/caddy/Caddyfile` |
| Config neuladen | `systemctl reload caddy` |
| Caddy-Live-Logs | `journalctl -u caddy -f` |
| HTTP-Access-Log | `tail -f /var/log/caddy/access.log \| jq` |
| Decisions auflisten | `cscli decisions list` |
| IP entbannen | `cscli decisions delete --ip 1.2.3.4` |
| Eigene IP whitelisten | `cscli decisions add --ip DEINE_IP --type whitelist --duration 999h` |
| Alerts der letzten Stunden | `cscli alerts list --since 24h` |
| Engine-Metriken | `cscli metrics` |
| Alle Bouncer auflisten | `cscli bouncers list` |
| Collection installieren | `cscli collections install <name>` |
| Hub-Updates ziehen | `cscli hub update && cscli hub upgrade` |

---

## Weiterführende Quellen

- [Caddy Dokumentation](https://caddyserver.com/docs/)
- [caddy-l4 Plugin](https://github.com/mholt/caddy-l4)
- [caddy-crowdsec-bouncer](https://docs.crowdsec.net/docs/bouncers/caddy/)
- [CrowdSec Dokumentation](https://docs.crowdsec.net/)
- [CrowdSec Hub (Detection-Szenarien)](https://hub.crowdsec.net/)

---

*Stand: 2026-04-26. Bei Fragen — du weißt ja, wer mich gebaut hat.*
