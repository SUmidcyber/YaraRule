rule NPM_Credential_Stealer_Typosquatting_Advanced {
    meta:
        description = "Çok katmanlı typosquatting saldırısı - Fake CAPTCHA, IP fingerprinting ve credential stealer tespiti"
        author = "Umid Mammadov"
        date = "2024-10-31"
        threat_level = "Critical"
        reference = "Socket.dev npm typosquatting research"
        version = "2.0"

    strings:
        //TYPOSQUATTED PACKAGE İSİMLERİ
        $typosquat_names = /(discordjs|etherjs|discord\.js|ether\.js|typescript\.js|deezcord\.js|ethes\.js|ethets\.js|nodemon\.js|react-router-dom\.js|zustand\.js)/ nocase
        
        // OTOMATİK ÇALIŞTIRMA PATTERN'LERİ
        $install_hooks = /(preinstall|postinstall|install)/ nocase
        $auto_execute = /(node\s+install\.js|npm\s+run|auto-run|autorun)/ nocase
        $immediate_exec = /(require\(['\"][^'\"]+['\"]\)|import\([^)]+\))/ nocase
        
        // FAKE CAPTCHA İNDİKLERİ
        $captcha_indicators = /(captcha|verify|human|robot|bot_check|validation)/ nocase
        $fake_ui = /(document\.write|innerHTML|alert|prompt|confirm)/ nocase
        $browser_trigger = /(window\.open|location\.href|fetch|XMLHttpRequest)/ nocase
        
        // IP FINGERPRINTING 
        $ip_services = /(ipify|ipapi|ipinfo|getip|whatismyip)/ nocase
        $ip_endpoints = /(195\.133\.79\.43|http:\/\/195\.133\.79\.43\/get_current_ip|api\.ipify\.org)/ ascii
        $geo_location = /(country|city|region|location|latitude|longitude)/ nocase
        $network_info = /(navigator\.userAgent|platform|language|timezone)/ nocase
        
        // CREDENTIAL STEALER PAYLOADLARI
        $credential_targets = /(\.env|config|password|token|key|secret|auth)/ nocase
        $file_operations = /(fs\.readFile|fs\.writeFile|fs\.copyFile|require\('fs'\))/ nocase
        $data_exfiltration = /(POST|fetch|axios|http\.request|FormData)/ nocase
        $base64_encode = /(btoa|atob|Buffer\.from|base64)/ nocase
        
        // ENCODE/DECODE MANEVRA 
        $obfuscation = /(eval\(|Function\(|fromCharCode|charCodeAt|unescape)/ nocase
        $hex_encoded = /(\\x[0-9a-f]{2}){4,}/ ascii
        $long_strings = /(\^|\%5E|\%0A|\%03|\%0D|\%15|\%08|\%0E|\%18)/ ascii
        
        // MULTI-STAGE INDICATORS 
        $multi_stage = /(stage|phase|level|download|execute|payload)/ nocase
        $conditional_exec = /(if\(|switch\(|ternary|condition)/ nocase
        $platform_check = /(process\.platform|win32|linux|darwin|os\.platform)/ nocase
        $data_extractor = /(data_extracter|extract|collect|gather)/ nocase

    condition:
        (
            // Typosquatting paket isimleri Senaryo 1
            (2 of ($typosquat_names)) or
             
            // Otomatik çalıştırma + Fake CAPTCHA kombinasyonu Senaryo 2
            (
                (1 of ($install_hooks)) and 
                (1 of ($captcha_indicators)) and
                (1 of ($fake_ui))
            ) or
            
            // IP fingerprinting + Credential stealing kombinasyonu Senaryo 3
            (
                (1 of ($ip_services) or filesize < 100KB) and
                (1 of ($credential_targets)) and
                (1 of ($file_operations))
            ) or
            
            // Multi-stage + Obfuscation kombinasyonu Senaryo 4
            (
                (1 of ($multi_stage)) and
                (1 of ($obfuscation)) and
                (filesize < 200KB) 
            ) or
            
            // Doğrudan kötü amaçlı IP/endpoint referansları Senaryo 5
            (1 of ($ip_endpoints)) or
            
            // Platforma özel payload indirme Senaryo 6
            (
                (1 of ($platform_check)) and
                (1 of ($data_extractor))
            )
        ) and 
        not filesize > 5MB and 
        not contains("MIT License") and  
        not contains("README.md") 
}