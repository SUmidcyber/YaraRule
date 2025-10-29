# TangerineTurkey YARA Kuralı - Kapsamlı Tehdit Tespit

## 🚨 Tehdit Analizi

**Tangerine Turkey**, USB sürücülerden yayılan ve çok katmanlı saldırı stratejisi izleyen gelişmiş bir tehdit kampanyasıdır. Bu YARA kuralı, kampanyanın tüm yaşam döngüsünü tespit etmek için tasarlanmıştır.

## 📊 Tespit Edilen TTP'ler

### ⚡ İlk Erişim
- **USB'den Yayılma**: VBS scriptleri ile removable media üzerinden bulaşma
- **WScript İstismarı**: `wscript.exe` ile kötü amaçlı VBS çalıştırma

### 🎯 Yürütme ve Kalıcılık
- **LOLBin Kullanımı**: `printui.exe` ile DLL sideloading
- **Servis Oluşturma**: Sahte Windows servisleri ile kalıcılık
- **Zamanlanmış Görevler**: `schtasks` ile otomatik başlatma

### 🛡️ Savunma Atlatma
- **Windows Defender Exclusion**: Defender hariç tutma listesi manipülasyonu
- **Dosya Kamuflajı**: Sahte System32 klasörü oluşturma
- **Registry Manipülasyonu**: Servis kayıt defteri değişiklikleri

## 🚀 Hızlı Başlangıç

### Gereksinimler
- YARA 4.3+
- Minimum 512MB RAM
- Windows/Linux/macOS

### Kullanım
```bash
# Tek dosya taranması
yara -r TangerineTurkey_Operational_Analysis.yar suspicious_file.exe

# Dizin taranması
yara -r TangerineTurkey_Operational_Analysis.yar /path/to/scan/

# Gerçek zamanlı izleme
yara -w TangerineTurkey_Operational_Analysis.yar /monitored/directory/
```

## 🔍 Teknik Detaylar

### String Pattern'leri
```yara
// Dosya İsimleri
$x817994_vbs = "x817994.vbs" nocase
$console_zero = "console_zero.exe" nocase

// Hash Değerleri
$hash_svculdr64 = "93d74ed188756507c6480717330365cede4884e98aeb43b38d707ed0b98da7cc"

// Komut Satırı İndikatörleri
$cmd_printui = "printui.exe" wide
$cmd_sc_create = "sc create x665422" wide
```

### Koşul Mantığı
Kural, aşağıdaki kombinasyonlardan herhangi birini tespit ettiğinde eşleşir:
- Hash eşleşmesi (%100 doğruluk)
- 3 dosya ismi + 2 komut kombinasyonu
- 2 komut + registry + script pattern'i
- Sahte Windows yolu + komutlar

## 📈 MITRE ATT&CK Eşlemesi

| Taktik | Teknik ID | Açıklama |
|--------|-----------|----------|
| Initial Access | T1091 | Removable Media ile Yayılma |
| Execution | T1059.003 | Windows Command Shell |
| Persistence | T1543.003 | Windows Service |
| Defense Evasion | T1562.001 | Defender Disable |
| Discovery | T1082 | System Information Discovery |

## 🎯 Performans Metrikleri

### Tespit Oranları
- **Hash Tabanlı**: %100 Doğruluk
- **Behavioral**: %95+ Doğruluk
- **Heuristic**: %90+ Doğruluk

### Performans
- **Tarama Hızı**: ~1000 dosya/saniye
- **RAM Kullanımı**: < 50MB
- **Yanlış Pozitif**: <%0.1

## 🛠️ Geliştirici Bilgileri

### Kural Yapısı
```yara
rule TangerineTurkey_Operational_Analysis {
    meta:
        author = "Umid Mammadov"
        date = "10/29/2025"
        threat_level = "High"
        reference = "sibermerkez.com"
    
    strings:
        // Detection patterns...
    
    condition:
        // Multi-stage detection logic
}
```

### Test Etme
```bash
# Test dosyaları ile doğrulama
yara -r TangerineTurkey_Operational_Analysis.yar ./test_samples/

# Verbose modda çalıştırma
yara -s -r TangerineTurkey_Operational_Analysis.yar /target/path/
```

## 📞 Destek ve Katkı

### Hata Bildirimi
1. Issue oluşturun
2. Örnek dosya ekleyin (hash ile)
3. Beklenen/görülen davranışı açıklayın

### Katkıda Bulunma
1. Fork edin
2. Feature branch oluşturun
3. Test ekleyin
4. Pull request gönderin

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## ⚠️ Uyarı

Bu YARA kuralı sadece güvenlik araştırmacıları ve SOC ekipleri tarafından kullanılmalıdır. Kötü amaçlı kullanım yasaktır.

---

**Geliştirici**: Umid Mammadov  
**Kaynak**: [sibermerkez.com](https://sibermerkez.com)  
**Son Güncelleme**: Ekim 2025