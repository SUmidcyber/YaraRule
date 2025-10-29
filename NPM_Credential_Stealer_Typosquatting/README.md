# 🚨 NPM Typosquatting Avcısı

## ⚡ **Ne Yaptık?**
Geliştiricileri kandıran **sahte npm paketlerini** otomatik tespit eden bir güvenlik radarı geliştirdik!

## 🎯 **Neden Önemli?**
- **Popüler paketlere benzer isimlerle** geliyorlar (`discordjs` → `deezcord.js`)
- **Kurulur kurulmaz otomatik çalışıyorlar**
- **Kimlik bilgilerinizi çalıyorlar** (.env, token, şifreler)
- **IP'nizi izliyor ve fake CAPTCHA gösteriyorlar**

## 🔍 **Nasıl Çalışıyor?**
```bash
# Tek komutla tüm projeni tara
yara -r npm_avcisi.yar ./node_modules/
```

**6 Farklı Saldırı Senaryosunu Tespit Eder:**
1. 🎭 **Sahte paket isimleri**
2. ⚡ **Otomatik çalıştırma tuzakları**  
3. 📍 **IP izleme sistemleri**
4. 🕵️ **Kimlik bilgisi hırsızlığı**
5. 🎪 **Çok aşamalı saldırılar**
6. 🔒 **Şifrelenmiş kötü amaçlı kod**

## 🛡️ **Anında Koruma**
```javascript
// BU KÖTÜ AMAÇLI KODU TESPİT EDER:
require('discordjs'); // 🚨 TYPO ALERT!
// → Gerçek: 'discord.js', Sahte: 'discordjs'

// Kurulunca otomatik çalışır:
// 1. 📍 IP'nizi kaydeder
// 2. 🕵️ .env dosyanızı okur  
// 3. 📤 Verileri hacker'a gönderir
```

## 🚀 **Hemen Kullan**
```bash
# Projende güvenlik taraması yap
yara NPM_Credential_Stealer_Typosquatting.yar şüpheli-paket.js

# Tüm node_modules'i tara  
yara -r NPM_Credential_Stealer_Typosquatting.yar ./node_modules/
```

**⚠️ Uyarı:** Bu kural, projende gizlenmiş npm tuzaklarını ortaya çıkarır!