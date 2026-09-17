# PySIEM Mimari Dokumani

## Genel Bakis

PySIEM, moduler bir mimari ile tasarlanmistir. Her bilesen kendi sorumluluk
alanina sahip ve bagimsiz olarak test edilebilir sekilde gelistirilmistir.

## Bilesenler

### 1. Log Collector (collector.py)

Log dosyalarini ve dizinlerinden ham satirlari toplar.

Sorumluluklar:
- Dosya okuma
- Dizin tarama
- Encoding hatasi toleransi

### 2. Log Parser (parser.py)

Ham log satirlarini yapilandirilmis RawEvent nesnelerine donusturur.

Desteklenen formatlar:
- SSH loglari (Failed password, Accepted password, Invalid user)
- Web server access loglari (Apache/Nginx formati)
- Uygulama loglari (seviye bazli)
- Syslog

### 3. Event Normalizer (normalizer.py)

Farkli kaynaklardan gelen olaylari ortak bir modele donusturur ve zenginlestirir.

Islemler:
- IP adresi dogrulama
- Severity zenginlestirme
- Saldiri patterni tespiti (SQL injection, command injection)
- Supheli path tespiti
- Event type siniflandirma

### 4. Detection Engine (detection.py)

Rule-based tespit motoru. Kurallari olaylar uzerinde degerlendirir.

Tespit tipleri:
- Brute force
- Basarisiz denemeler sonrasi basarili giris
- Pattern matching (SQL injection, command injection)
- Web dizin taramasi
- Supheli kimlik dogrulama
- Yetki yukseltme

### 5. Correlation Engine (correlation.py)

Olaylar arasindaki iliskileri zaman penceresi icinde analiz eder.

Korelasyon turleri:
- Basarisiz denemeler + basarili giris
- Zaman penceresi icerisinde brute force
- Lateral movement (SSH uzerinden coklu kullanici)

### 6. Alert Manager (alert.py)

Alert olusturma, deduplication ve yonetim islemlerini yapar.

Ozellikler:
- Alert olusturma
- Deduplication (ayni kural + IP icin tekrarlanan alertleri onleme)
- Durum guncelleme
- Filtreleme

### 7. Storage (storage.py)

SQLite veritabani ile tum veri saklama islemlerini yonetir.

Tablolar:
- events: Olaylar
- alerts: Alertler
- rules: Tespit kurallari
- detection_log: Tespit loglari

### 8. Report Generator (report.py)

Veritabanindaki verilerden raporlar uretir.

Formatlar:
- Text (terminal)
- JSON
- CSV

### 9. CLI (cli.py)

Komut satiri arayuzu. Tum modulleri ornekler.

## Veri Akisi

```
1. Kullanici: python main.py ingest data/samples/auth.log
2. LogCollector: Dosyayi okur, ham satirlari dondurur
3. LogParser: Her satiri RawEvent'e parse eder
4. EventNormalizer: Olaylari dogrular ve zenginlestirir
5. Storage: Normalize edilmis olaylari SQLite'a kaydeder
6. DetectionEngine: Kurallari olaylar uzerinde degerlendirir
7. CorrelationEngine: Zaman bazli korelasyon yapar
8. AlertManager: Tespit sonuclarindan alert olusturur
9. Kullanici: python main.py alerts ile sonuclari gorur
```

## Konfigurasyon

Konfigurasyon degerleri su kaynaklardan okunur:

1. Varsayilan degerler (AppConfig sinifi)
2. Ortam degiskenleri (PYSIEM_*)

Onemli konfigurasyon parametreleri:

| Parametre | Varsayilan | Aciklama |
|-----------|-----------|----------|
| brute_force_threshold | 5 | Brute force icin esik degeri |
| correlation_time_window | 300 | Korelasyon penceresi (saniye) |
| failed_login_threshold | 3 | Basarisiz giris esik degeri |
| dedup_window | 60 | Alert deduplication penceresi |

## Guvenlik

- SQL injection'a karsi parameterized queries kullanilir
- Kullanici girdileri normalize edilir
- Dosya path'leri kontrol edilir
- Secret veya credential kullanilmaz
- Ornek loglar tamamen sentetiktir
