# Event Modeli Dokumani

## Genel Bakis

PySIEM, farkli log kaynaklarindan gelen verileri ortak bir event modeline
donusturur. Bu model, tum olaylari tutarli bicimde temsil eder.

## Normalized Event Alanlari

| Alan | Tur | Zorunlu | Aciklama |
|------|-----|---------|----------|
| id | string | Evet | Benzersiz olay kimligi (UUID) |
| timestamp | datetime | Evet | Olay zamani |
| source | string | Evet | Log kaynagi (sshd, webserver, application) |
| event_type | enum | Evet | Olay tipi |
| username | string | Hayir | Ilgili kullanici adi |
| source_ip | string | Hayir | Kaynak IP adresi |
| destination_ip | string | Hayir | Hedef IP adresi |
| port | int | Hayir | Port numarasi |
| status | string | Hayir | Olay durumu |
| message | string | Evet | Olay mesaji |
| severity | enum | Evet | Olay onceligi |
| raw_log | string | Evet | Ham log satiri |
| hostname | string | Hayir | Sunucu adi |
| protocol | string | Hayir | Protokol (ssh, http) |

## Event Tipleri

### auth_success

Basarili kimlik dogrulama olayi.

Ornek: "Accepted password for admin from 192.168.1.20 port 45122 ssh2"

### auth_failure

Basarisiz kimlik dogrulama olayi.

Ornek: "Failed password for root from 192.168.1.50 port 43122 ssh2"

### web_request

HTTP istek olayi.

Ornek: "GET /index.html HTTP/1.1" 200 5120

### app_log

Uygulama log olayi.

Ornek: "ERROR Database connection timeout after 30 seconds"

### system_event

Sistem log olayi (syslog).

Ornek: "systemd[1]: Started PySIEM Collector Service"

### unknown

Taninamayan format.

## Severity Seviyeleri

| Seviye | Deger | Aciklama |
|--------|-------|----------|
| LOW | 1 | Normal aktivite, dikkat gerektirmez |
| MEDIUM | 2 | Dikkat gerektiren durum |
| HIGH | 3 | Onemli guvenlik olayi |
| CRITICAL | 4 | Kritik guvenlik onlemi gereken durum |

### Severity Belirleme Kurallari

1. **LOW**: Normal basarili girisler, bilgi amacli loglar
2. **MEDIUM**: Basarisiz giris denemeleri, 4xx HTTP hatalari
3. **HIGH**: 5xx HTTP hatalari, root kullanicisiyla girisler,
   SQL/command injection desenleri
4. **CRITICAL**: Tespit edilen saldiri patternleri

## Desteklenen Log Formatlari

### SSH Loglari

```
Sep 16 18:31:22 server sshd[1234]: Failed password for root from 192.168.1.50 port 43122 ssh2
Sep 16 18:32:10 server sshd[1235]: Accepted password for admin from 192.168.1.20 port 45122 ssh2
Sep 16 18:33:00 server sshd[1236]: Invalid user testuser from 10.0.0.1 port 46000 ssh2
```

### Web Server Loglari (Apache/Nginx formati)

```
192.168.1.10 - - [16/Sep/2026:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 5120
10.0.0.50 - - [16/Sep/2026:08:06:01 +0000] "GET /admin HTTP/1.1" 403 512
```

### Uygulama Loglari

```
Sep 16 08:10:00 app-server application[2001]: ERROR Database connection timeout after 30 seconds
Sep 16 08:15:00 app-server application[2002]: INFO Scheduled backup completed
```

### Syslog

```
Sep 16 08:00:01 web-server systemd[1]: Started PySIEM Collector Service
Sep 16 08:05:00 web-server kernel: [  300.000000] TCP: Possible SYN flooding
```

## Ornek Event Donusumleri

### SSH Brute Force

Ham Log:
```
Sep 16 08:05:12 server sshd[1002]: Failed password for root from 10.0.0.50 port 50200 ssh2
```

Normalized Event:
```json
{
  "id": "a1b2c3d4-...",
  "timestamp": "2026-09-16T08:05:12",
  "source": "sshd",
  "event_type": "auth_failure",
  "username": "root",
  "source_ip": "10.0.0.50",
  "port": 50200,
  "status": "failed",
  "message": "Basarisiz sifre denemesi: root",
  "severity": "MEDIUM",
  "hostname": "server",
  "protocol": "ssh"
}
```

### Web Request

Ham Log:
```
192.168.1.10 - - [16/Sep/2026:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 5120
```

Normalized Event:
```json
{
  "id": "e5f6g7h8-...",
  "timestamp": "2026-09-16T08:00:01",
  "source": "webserver",
  "event_type": "web_request",
  "source_ip": "192.168.1.10",
  "status": "200",
  "message": "GET /index.html - 200",
  "severity": "LOW",
  "protocol": "http",
  "extra": {
    "method": "GET",
    "path": "/index.html",
    "response_code": 200
  }
}
```
