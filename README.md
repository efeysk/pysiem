# PySIEM
asd
Mini Security Information and Event Management Sistemi

## Proje Hakkinda

PySIEM, gercek bir SIEM'in basitlestirilmis egitim ve portfoy versiyonudur.
Farkli log kaynaklarindan gelen verileri toplar, analiz eder, tespit kurallarini
uygular ve guvenlik alertleri olusturur.

Bu proje, log toplama, parsing, normalizasyon, tespit, korelasyon, alert yonetimi
ve raporlama gibi temel SIEM ozelliklerini icerir.

## Ozellikler

- Coklu log kaynagi destegi (SSH, web server, uygulama, sistem loglari)
- Log toplama ve dosya okuma
- Pattern-based log parsing
- Ortak event modeline normalizasyon
- Rule-based tespit motoru
- Event correlation motoru
- Alert olusturma ve yonetimi
- Alert deduplication
- SQLite veritabani depolamasi
- JSON ve CSV raporlama
- MITRE ATT&CK teknik eslestirmesi
- CLI arayuzu
- Docker destegi

## Mimari

```
Log Sources
|
v
Log Collector
|
v
Log Parser
|
v
Event Normalizer
|
v
Detection Engine
|
v
Correlation Engine
|
v
Alert Manager
|
v
SQLite Storage
|
+----> CLI
|
+----> Reporting
```

## Kurulum

### Gereksinimler

- Python 3.11 veya daha yuksek

### Kurulum Adimlari

```bash
# Repository'yi klonlayin
git clone https://github.com/efeysk/pysiem.git
cd pysiem

# Virtual environment olusturun
python -m venv .venv

# Virtual environment'i aktive edin
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Projei yukleyin
pip install -e .
```

### Testleri Calistirin

```bash
pip install pytest
pytest
```

## Kullanim

### Log Ingest

```bash
python main.py ingest data/samples/auth.log
python main.py ingest data/samples/web.log
python main.py ingest data/samples/application.log
python main.py ingest data/samples/system.log
```

### Olay Listeleme

```bash
python main.py events
python main.py events --limit 100
python main.py events --severity HIGH
python main.py events --type auth_failure
python main.py events --ip 10.0.0.50
```

### Alert Listeleme

```bash
python main.py alerts
python main.py alerts --severity CRITICAL
python main.py alerts --status NEW
```

### Tespit Calistirma

```bash
python main.py detect
```

### Raporlama

```bash
python main.py report
python main.py report --format json
python main.py report --format csv
```

### Kurallari Listeleme

```bash
python main.py rules
```

### Sistem Durumu

```bash
python main.py status
```

### Alert Durumu Guncelleme

```bash
python main.py alert-update <alert_id> INVESTIGATING
python main.py alert-update <alert_id> RESOLVED
python main.py alert-update <alert_id> FALSE_POSITIVE
```

## CLI Komutlari

| Komut | Aciklama |
|-------|----------|
| `ingest` | Log dosyasini sisteme aktar |
| `events` | Olaylari listele |
| `alerts` | Alertleri listele |
| `detect` | Tespit motorunu calistir |
| `report` | Rapor olustur |
| `rules` | Yuklenen kurallari listele |
| `status` | Sistem durumunu goster |
| `alert-update` | Alert durumunu guncelle |

## Ornekler

### Tam Pipeline Ornegi

```bash
# 1. Ornek log dosyasini ingest edin
python main.py ingest data/samples/auth.log

# 2. Olaylari kontrol edin
python main.py events

# 3. Tespitleri calistirin
python main.py detect

# 4. Alertleri inceleyin
python main.py alerts

# 5. Rapor olusturun
python main.py report
```

## Tespit Kurallari

### Desteklenen Tespitler

| Kural | Aciklama | MITRE ATT&CK |
|-------|----------|-------------|
| SSH Brute Force | Ayni IP'den cok sayida basarisiz SSH girisi | T1110 |
| Coklu Basarisiz Kimlik Dogrulama | Farkli kullanici adlariyla basarisiz denemeler | T1110.003 |
| Basarisiz Denemeler Sonrasi Basarili Giris | Supheli hesap ele gecirme patterni | T1110.001 |
| Supheli Kimlik Dogrulama | Sipheli kullanici adlariyla denemeler | T1078 |
| Web Dizin Taramasi | Cok sayida farkli web yolu taranmasi | T1595.003 |
| SQL Injection | HTTP isteklerinde SQL injection deseni | T1190 |
| Command Injection | HTTP isteklerinde command injection deseni | T1059 |
| Yetki Yukseltme | Sudo/root ile supheli aktivite | T1068 |

### Kurallari Ozellestirme

Kurallar `rules/default_rules.json` dosyasinda tanimlidir.
Her kural su alanlari icerir:

```json
{
  "id": "BRUTE-FORCE-SSH",
  "name": "SSH Brute Force",
  "description": "Ayni IP'den cok sayida basarisiz SSH girisi",
  "severity": "HIGH",
  "threshold": 5,
  "time_window": 300,
  "mitre_technique": "T1110",
  "rule_type": "brute_force",
  "enabled": true
}
```

## MITRE ATT&CK

PySIEM asagidaki MITRE ATT&CK tekniklerini destekler:

| Teknik ID | Aciklama | Kullanim |
|-----------|----------|----------|
| T1110 | Brute Force | SSH basarisiz giris tespiti |
| T1110.001 | Password Guessing | Tek kullaniciya yonelik brute force |
| T1110.003 | Password Spraying | Coklu kullaniciya yonelik brute force |
| T1078 | Valid Accounts | Gecersiz/supheli kullanici adi tespiti |
| T1190 | Exploit Public-Facing Application | SQL injection tespiti |
| T1059 | Command and Scripting Interpreter | Command injection tespiti |
| T1068 | Exploitation for Privilege Escalation | Yetki yukseltme tespiti |
| T1595.003 | Wordlist Scanning | Web dizin tarama tespiti |
| T1021.004 | Remote Services: SSH | Lateral movement tespiti |

## Testler

Testleri calistirmak icin:

```bash
pytest
```

Kapsamli test raporu icin:

```bash
pytest --cov=pysiem --cov-report=html
```

### Test Kapsami

- Parser testleri: Farkli log formatlari icin parsing
- Normalizer testleri: IP dogrulama, severity zenginlestirme
- Detection testleri: Brute force, pattern match, yetki yukseltme
- Correlation testleri: Zaman penceresi korelasyonu
- Storage testleri: Veritabani islemleri
- Alert testleri: Alert olusturma, deduplication, durum guncelleme
- CLI testleri: Komut satiri arayuzu

## Proje Yapisi

```
mini-siem/
|
+-- src/
|   +-- pysiem/
|       +-- __init__.py
|       +-- cli.py
|       +-- config.py
|       +-- models.py
|       +-- collector.py
|       +-- parser.py
|       +-- normalizer.py
|       +-- detection.py
|       +-- correlation.py
|       +-- alert.py
|       +-- storage.py
|       +-- report.py
|       +-- logging_config.py
|
+-- tests/
|   +-- test_parser.py
|   +-- test_normalizer.py
|   +-- test_detection.py
|   +-- test_correlation.py
|   +-- test_storage.py
|   +-- test_alert.py
|   +-- test_cli.py
|
+-- data/
|   +-- samples/
|       +-- auth.log
|       +-- web.log
|       +-- application.log
|       +-- system.log
|
+-- rules/
|   +-- default_rules.json
|
+-- docs/
|   +-- architecture.md
|   +-- detection-rules.md
|   +-- events.md
|
+-- reports/
|
+-- main.py
+-- pyproject.toml
+-- README.md
+-- LICENSE
+-- .gitignore
+-- Dockerfile
+-- docker-compose.yml
```

## Ornek Alert

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "rule_id": "BRUTE-FORCE-SSH",
  "rule_name": "SSH Brute Force",
  "severity": "HIGH",
  "status": "NEW",
  "source_ip": "10.0.0.50",
  "timestamp": "2026-09-16T08:05:39",
  "description": "10.0.0.50 adresinden 10 basarisiz giris denemesi tespit edildi.",
  "mitre_technique": "T1110",
  "related_events": ["Sep 16 08:05:12 server sshd[1002]: Failed password for root from 10.0.0.50 ..."],
  "details": {
    "failure_count": 10,
    "time_range_seconds": 27.0,
    "usernames_tried": ["root"]
  }
}
```

## Gelecekte Eklenebilecekler

- Surucusuz log toplama (agent-based)
- Daha fazla log kaynagi destegi (Windows Event Log, Firewall, IDS/IPS)
- Gercek zamanli izleme dashboardu
- E-posta bildirimleri
- SIEM entegrasyonu (Syslog,CEF)
- Daha gelismis correlation kurallari
- Machine Learning tabanli anomaly detection
- Web arayuzu
- Multi-tenant destek

## Lisans

MIT License - Detaylar icin LICENSE dosyasina bakin.
