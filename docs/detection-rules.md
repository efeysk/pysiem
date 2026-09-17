# Tespit Kurallari Dokumani

## Genel Bakis

PySIEM, rule-based bir tespit motoruna sahiptir. Kurallar
`rules/default_rules.json` dosyasinda tanimlidir.

## Kural Yapisi

Her kural su alanlari icerir:

| Alan | Tur | Aciklama |
|------|-----|----------|
| id | string | Benzersiz kural kimligi |
| name | string | Kural adi |
| description | string | Kural aciklamasi |
| severity | enum | LOW, MEDIUM, HIGH, CRITICAL |
| threshold | int | Tetikleme esik degeri |
| time_window | int | Zaman penceresi (saniye) |
| mitre_technique | string | MITRE ATT&CK teknik kodu |
| rule_type | string | Kural tipi |
| enabled | bool | Kuralin aktif olup olmadigi |
| pattern | string | Regex deseni (pattern_match icin) |

## Kural Tipleri

### brute_force

Belirli bir IP adresinden belirli sayida basarisiz giris denemesi tespit eder.

Parametreler:
- threshold: Minimum basarisiz deneme sayisi
- time_window: Zaman penceresi (saniye)

Ornek: 5 basarisiz SSH girisi 300 saniye icinde

MITRE ATT&CK: T1110

### failed_then_success

Basarisiz giris denemelerinden sonra basarili girisi tespit eder.
Bu pattern, brute force sonrasi hesap ele gecirmeyi isaretedebilir.

Parametreler:
- threshold: Minimum basarisiz deneme sayisi
- time_window: Zaman penceresi (saniye)

MITRE ATT&CK: T1110.001

### multi_failed_auth

Ayni IP adresinden farkli kullanici adlariyla yapilan basarisiz denemeleri
tespit eder (password spraying).

MITRE ATT&CK: T1110.003

### suspicious_auth

Supheli kullanici adlariyla yapilan giris denemelerini tespit eder.
Desteklenen supheli kullanici adlari:

- root, admin, administrator
- test, guest
- oracle, mysql, postgres
- www-data, nobody

MITRE ATT&CK: T1078

### web_scanning

Ayni IP adresinden cok sayida farkli web yolu taranmasini tespit eder.
Dizin tarama ve vulnerability scanning aktivitelerini yakalar.

Parametreler:
- threshold: Minimum taranan yol sayisi

MITRE ATT&CK: T1595.003

### pattern_match

Genelregex desen eslestirmesi yapar. SQL injection ve command injection
tespitleri icin kullanilir.

Desteklenen patternler:

SQL Injection:
- UNION SELECT
- SELECT * FROM
- DROP TABLE
- INSERT INTO
- DELETE FROM
- OR 1=1

Command Injection:
- ;command
- |command
- `command`
- $(command)

MITRE ATT&CK: T1190 (SQL Injection), T1059 (Command Injection)

### privilege_escalation

Sudo veya root ile yapilan supheli aktiviteleri tespit eder.

Tespit edilen patternler:
- sudo ile root erisimi
- root hesabiyla uzak giris
- Kullanici degistirme denemesi (su -)

MITRE ATT&CK: T1068

## MITRE ATT&CK Eslesme Tablosu

| Teknik ID | Teknik Adi | Kullanilan Kural |
|-----------|-----------|-----------------|
| T1110 | Brute Force | BRUTE-FORCE-SSH |
| T1110.001 | Password Guessing | FAILED-THEN-SUCCESS |
| T1110.003 | Password Spraying | MULTI-FAILED-AUTH |
| T1078 | Valid Accounts | SUSPICIOUS-AUTH |
| T1190 | Exploit Public-Facing App | SQL-INJECTION |
| T1059 | Command and Scripting Interpreter | CMD-INJECTION |
| T1068 | Exploitation for Priv Esc | PRIV-ESCALATION |
| T1595.003 | Wordlist Scanning | WEB-DIR-SCANNING |
| T1021.004 | Remote Services: SSH | CORR-LATERAL-MOVEMENT |

## Yeni Kural Ekleme

Yeni bir kural eklemek icin `rules/default_rules.json` dosyasina
su formatta bir JSON nesnesi ekleyin:

```json
{
  "id": "YENI-KURAL",
  "name": "Kural Adi",
  "description": "Kural aciklamasi",
  "severity": "MEDIUM",
  "threshold": 5,
  "time_window": 300,
  "mitre_technique": "T1110",
  "rule_type": "brute_force",
  "enabled": true,
  "pattern": ""
}
```

Kural tipine gore farkli parametreler gerektirebilir:

- brute_force: threshold, time_window
- pattern_match: pattern (regex)
- web_scanning: threshold
- failed_then_success: threshold, time_window
