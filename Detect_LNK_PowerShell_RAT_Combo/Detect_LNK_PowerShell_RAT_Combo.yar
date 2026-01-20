/*
    YARA Rule Set: APT Covert Access Operation Hunter
    Author: Gemini AI (Security Research Partner)
    Date: 2026-01-19
    Reference: Seqrite Report - Operation Covert Access (Argentina Judicial Sector Target)
    Description: Advanced detection for Weaponized LNKs, Obfuscated PowerShell Droppers, and C# RAT payloads.
    Classification: TLP:WHITE
*/

import "pe"

// ---------------------------------------------------------------------------
// AŞAMA 1: BAŞLANGIÇ ERİŞİMİ (INITIAL ACCESS)
// Hedef: Kurbanı kandırmak için kullanılan sinsi LNK dosyaları
// ---------------------------------------------------------------------------
rule APT_Weaponized_LNK_Phishing {
    meta:
        description = "Saldırganların cmd/powershell çalıştıran gizli LNK dosyalarını tespit eder."
        author = "Gemini AI"
        severity = "High"
        mitre_att = "T1566.002, T1059.001" // Spearphishing Attachment, PowerShell
        date = "2026-01-19"

    strings:
        // LNK Dosya Başlığı (Header)
        $lnk_header = { 4C 00 00 00 01 14 02 00 }

        // Kabuk Komutları (Büyük/küçük harf duyarlılığı olmadan ve geniş varyasyonlu)
        $shell_cmd = "cmd.exe" nocase wide ascii
        $shell_ps  = "powershell" nocase wide ascii
        $shell_pwsh = "pwsh" nocase wide ascii // PowerShell Core varyasyonu

        // Şüpheli Parametreler (Saldırının imzası)
        $flag_hidden = "-w hidden" nocase wide ascii
        $flag_style  = "WindowStyle Hidden" nocase wide ascii
        $flag_enc    = "-enc" nocase wide ascii
        $flag_nop    = "-nop" nocase wide ascii
        $flag_c      = "/c " nocase wide ascii

        // Ağ İndiricileri (LNK içinden dosya çekme girişimi)
        $net_curl = "curl" nocase wide ascii
        $net_wget = "wget" nocase wide ascii
        $net_iwr  = "iwr" nocase wide ascii
        $net_bits = "bitsadmin" nocase wide ascii

    condition:
        // 1. Dosya bir LNK olmalı
        $lnk_header at 0 and filesize < 50KB and
        
        // 2. Bir kabuk (shell) çağırmalı
        ($shell_cmd or $shell_ps or $shell_pwsh) and
        
        // 3. Gizlilik veya kodlanmış komut parametreleri içermeli
        (
            ($flag_c and ($flag_hidden or $flag_style)) or 
            ($flag_enc and $flag_nop) or
            1 of ($net_*)
        )
}

// ---------------------------------------------------------------------------
// AŞAMA 2: YÜRÜTME & GİZLENME (EXECUTION & DEFENSE EVASION)
// Hedef: Bellekte veya diskte çalışan karmaşık PowerShell betikleri
// ---------------------------------------------------------------------------
rule APT_PowerShell_Obfuscated_Dropper {
    meta:
        description = "Base64 ve sıkıştırma yöntemleriyle gizlenmiş PowerShell indiricilerini avlar."
        author = "Gemini AI"
        severity = "Critical"
        mitre_att = "T1027, T1059.001" // Obfuscated Files, PowerShell
        
    strings:
        // İndirme Sinyalleri (Download Primitives)
        $web_client = "System.Net.WebClient" nocase
        $dl_string  = ".DownloadString(" nocase
        $dl_data    = ".DownloadData(" nocase

        // Kod Çözme ve Çalıştırma Sinyalleri (Decoding & Execution)
        $b64_decode = "[System.Convert]::FromBase64String" nocase
        $mem_stream = "IO.MemoryStream" nocase
        $gzip_strm  = "IO.Compression.GzipStream" nocase
        $invoke_exp = "Invoke-Expression" nocase
        $iex_short  = "IEX " nocase

        // Değişken Manipülasyonu (Saldırganlar $env:public gibi yolları sever)
        $path_env   = "$env:public" nocase
        $path_temp  = "$env:temp" nocase

    condition:
        // Sadece powershell dosyalarında veya bellek dökümlerinde ara
        // Base64 çözme işlemi VE bellek akışı VE sıkıştırma açma işlemi bir aradaysa %99 zararlıdır.
        ($b64_decode and $mem_stream and $gzip_strm) or
        
        // Veya İndirme komutu ile Çalıştırma komutu bir aradaysa
        (1 of ($web_client, $dl_string, $dl_data) and ($invoke_exp or $iex_short))
}

// ---------------------------------------------------------------------------
// AŞAMA 3: PAYLOAD (MALWARE/RAT)
// Hedef: Son aşamada bulaşan Casus Yazılım (RAT)
// ---------------------------------------------------------------------------
rule APT_Generic_Covert_RAT_Payload {
    meta:
        description = "Kalıcılık sağlayan, klavye dinleyen ve C2 sunucusuna bağlanan genel RAT imzası."
        author = "Gemini AI"
        severity = "High"
        mitre_att = "T1547.001, T1056.001" // Registry Run Keys, Keylogging
        
    strings:
        // 1. Kalıcılık (Persistence) - Olmazsa olmazdır
        $reg_run      = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $reg_runonce  = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase wide ascii
        $startup_path = "Start Menu\\Programs\\Startup" nocase wide ascii

        // 2. Casusluk Yetenekleri (Spying Capabilities)
        // Kullanıcı penceresini ve tuş vuruşlarını izleme
        $api_keylog   = "GetAsyncKeyState" ascii
        $api_window   = "GetForegroundWindow" ascii
        $api_input    = "GetLastInputInfo" ascii
        
        // 3. .NET Göstergeleri (Rapordaki RAT .NET/C# tabanlı olabilir)
        $dotnet_mscor = "mscoree.dll" ascii
        $dotnet_rt    = "_CorExeMain" ascii

        // 4. Şüpheli Dosya Yolları (Artifacts)
        $susp_appdata = "AppData\\Roaming" nocase wide ascii
        $susp_local   = "AppData\\Local\\Temp" nocase wide ascii

    condition:
        // Dosya geçerli bir Windows çalıştırılabilir dosyası (EXE) olmalı
        uint16(0) == 0x5A4D and filesize < 5MB and
        
        // Dosya .NET tabanlı mı? (Opsiyonel ama doğruluğu artırır)
        ($dotnet_mscor or $dotnet_rt) and

        // Kalıcılık sağlamaya çalışıyor mu?
        1 of ($reg_run, $reg_runonce, $startup_path) and

        // Casusluk API'leri içeriyor mu?
        2 of ($api_*)
}