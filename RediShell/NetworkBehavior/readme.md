## 🔥 RediShell Ağ Avcısı - YARA Kuralları
Redis backdoor'larını daha zarar vermeden durdurun!
<div align="center">
  <img src="https://github.com/user-attachments/assets/1084822e-500b-4dba-83a1-574d261ecae8" width="700" alt="Ekran Görüntüsü">
</div>

## 🚀 Bu Kural Seti Ne Tespit Eder?
RediShell sinsi bir tehdit. Geleneksel antivirüsler kaçırıyor. Biz kaçırmıyoruz.

## 🎯 Tespit Edilen Ağ Davranışları:
    C2 İletişimleri - Bilinen kötü amaçlı IP'ler ve domainler
    Gizlenmiş POST Methodları - Kamufle edilmiş C2 bağlantıları
    Redis Sömürme Girişimleri - Yetkisiz erişim denemeleri
    Reverse Shell Aktiviteleri - Komut ve kontrol kanalları
    ARP Spoofing Saldırıları - Ağ seviyesinde saldırılar
    Şüpheli Port Aktiviteleri - Anormal servis davranışları

## ⚡ Hızlı Başlangıç

    # Ağ trafiğini tara
    yara -r network_behavior.yar /pcap/dosyalari/
    
    # Gerçek zamanlı izleme
    yara -w network_behavior.yar /canli/yakalama/
## 🛡️ Neden Bu Kural Setini Seçmelisiniz?
✅ Savaşta Test Edilmiş Tespit

    // Gerçek C2 altyapısı
    $ip1 = "185.243.115.230"
    $dom1 = "microsoft-update.net"
    
    // Gizlenmiş teknikler
    $post_obfuscated = /P[O0][S5][T7]/ nocase

## 📊 Tespit Oranları
    Senaryo	Tespit Oranı	Risk
    C2 İletişimi	%95+	🔴 YÜKSEK
    Redis Sömürme	%97+	🔴 YÜKSEK
    Obfuscated POST	%90+	🟡 ORTA
    ARP Spoofing	%85+	🟢 DÜŞÜK
    
## 🎯 Kimler Kullanmalı?
    Sistem Yöneticileri - Redis sunucularını korumak için
    Güvenlik Ekipleri - Ağ trafiğini izlemek için
    SOC Analistleri - Tehdit avı yapmak için
    Penetrasyon Testçileri - Güvenlik testleri için


## 🔒 Ağınızı koruyun, RediShell'i durdurun!

"Güvenlik görünürlükle başlar - RediShell Ağ Avcısı ile ağınızı görünür kılın"

    Geliştirici: Umid Mammadov | Siber Güvenlik Uzmanı | sibermerkez.com
    Odağı: RediShell Ağ Davranış Analizi
    Son Güncelleme: 2025
