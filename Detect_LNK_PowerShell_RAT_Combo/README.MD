# 🛡️ APT Covert Access Hunter (Seqrite Operation)

## 📋 Proje Hakkında (About)

**APT Covert Access Hunter**, özellikle Arjantin Adli Sektörü'nü ve kamu kurumlarını hedef alan gelişmiş siber casusluk operasyonlarını tespit etmek amacıyla geliştirilmiş, **kurumsal sınıf (Enterprise-Grade)** bir YARA kural setidir.

Bu proje, **Seqrite** tarafından raporlanan *"Operation Covert Access"* saldırı zincirini (Kill Chain) baz alır. Saldırganların kullandığı karmaşık kaçış tekniklerini (obfuscation), sinsi LNK dosyalarını ve bellekte çalışan (fileless) PowerShell tehditlerini analiz ederek, geleneksel antivirüslerin kaçırabileceği tehditleri yakalar.

> **Amaç:** Kurumların SOC (Güvenlik Operasyon Merkezi) ekiplerine, devlet destekli veya gelişmiş siber suç gruplerına (APT) karşı proaktif bir savunma hattı sunmaktır.

---

## 🚀 Özellikler (Key Features)

Bu kural seti, basit dize eşleşmelerinin ötesine geçerek **davranışsal analiz** yapar:

* **🕵️‍♂️ Çok Katmanlı Tespit:** Saldırının üç aşamasını da (Giriş, Yayılma, Yerleşme) ayrı ayrı hedefler.
* **🧠 Anti-Evasion (Atlatma Önleyici):** `powershell`, `pwsh`, `cmd`, `WindowStyle Hidden` gibi komutların Base64 ile gizlenmiş veya farklı varyasyonlarını algılar.
* **🎯 Düşük "False Positive" Oranı:** Sadece kötü niyetli kombinasyonları (Örn: LNK + PowerShell + Ağ Aktivitesi) hedefleyerek gereksiz alarmları önler.
* **🌍 MITRE ATT&CK Uyumu:** Kurallar, endüstri standardı olan MITRE çerçevesine tam uyumludur.

---

## 🛠️ Kurulum ve Kullanım (Usage)

Bu kural setini kullanmak için sisteminizde [YARA](https://virustotal.github.io/yara/) kurulu olmalıdır.

### 1. Dosyayı İndirin

Repo'yu klonlayın veya `APT_CovertAccess_Hunter.yar` dosyasını indirin.

### 2. Tarama Başlatın (Threat Hunting)

Tüm sistemi veya şüpheli bir dizini taramak için aşağıdaki komutu kullanın:

```powershell
# Windows (PowerShell)
.\yara64.exe -r .\APT_CovertAccess_Hunter.yar C:\Users\Public\

# Linux / Mac
yara -r APT_CovertAccess_Hunter.yar /home/user/Downloads/

```

* `-r`: Alt klasörleri de kapsayacak şekilde (recursive) tarar.

---

## 🔍 Tespit Kapsamı (Detection Coverage)

Bu kural seti aşağıdaki tehdit vektörlerini kapsar:

| Kural Adı | Hedef (Target) | MITRE ATT&CK ID | Açıklama |
| --- | --- | --- | --- |
| **APT_Weaponized_LNK_Phishing** | Başlangıç Erişimi | **T1566.002** | İçerisine zararlı `cmd` veya `powershell` komutları gömülmüş sahte LNK (Kısayol) dosyalarını yakalar. |
| **APT_PowerShell_Obfuscated_Dropper** | Çalıştırma & Gizlenme | **T1059.001, T1027** | Base64 ile şifrelenmiş ve `IEX` (Invoke-Expression) ile bellekte çalıştırılan indirici (dropper) betikleri tespit eder. |
| **APT_Generic_Covert_RAT_Payload** | Komuta & Kontrol | **T1547.001, T1056** | Sisteme yerleşen, Registry kayıtlarıyla kalıcılık sağlayan ve klavye hareketlerini izleyen (Keylogger) RAT yazılımlarını bulur. |

---

## ⚠️ Neden Bu Kurala İhtiyacınız Var?

Saldırganlar artık `.exe` dosyası göndermek yerine, güvenli görünen "Belge Kısayolları" (LNK) ve bellekte çalışan kodlar kullanıyor.

* **Geleneksel Antivirüsler:** Genellikle dosya imzasına bakar. LNK dosyasının içi sürekli değiştiği için kaçırabilirler.
* **APT Covert Access Hunter:** Dosyanın *neye benzediğine* değil, *ne yapmaya çalıştığına* bakar.

> *"Bir sistemin güvenliği, en zayıf halkanın görünürlüğü kadardır. Bu kurallar, o görünmez halkayı aydınlatmak için tasarlanmıştır."*

---

## 🤝 Katkıda Bulunma (Contributing)

Bu proje açık kaynaklıdır ve topluluk katkısına açıktır.

1. Fork edin.
2. Yeni bir dal (branch) oluşturun (`git checkout -b feature/YeniKural`).
3. Değişikliklerinizi commit edin.
4. Bir "Pull Request" gönderin.

---
