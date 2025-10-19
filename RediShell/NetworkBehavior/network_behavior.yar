import "pe"

rule RediShell_Network_Behavior {
    meta:
        description = "RediShell Network Behavior Detection"
        author = "Umid Mammadov"
        threat = "RediShell Backdoor - Redis exploitation & C2 communication"
    
    strings:
        // C2 sunuculari
        $ip1 = "185.243.115.230" nocase
        $ip2 = "45.133.216.177" nocase
        $ip3 = "107.189.30.237" nocase
        $ip4 = "91.92.245.121" nocase
        
        // Domainler
        $dom1 = "microsoft-update.net" nocase
        $dom2 = "windows-telemetry.com" nocase
        $dom3 = "azure-service.org" nocase
        $dom4 = "google-analytics.pro" nocase

        // Network Method
        $method1 = "POST" nocase
        $method2 = "PoSt" nocase
        $method3 = "pOsT" nocase
        $method4 = "post" nocase

        // Sleep behavior
        $sleep1 = "sleep" nocase
        $sleep2 = "Sleep" nocase
        $sleep3 = "SLEEP" nocase

        // Obfuscated POST methodları için regex
        $post_obfuscated = /P[O0][S5][T7]/ nocase

        // Obfuscated sleep için regex  
        $sleep_obfuscated = /s[l1][e3][e3]p/ nocase

        // Redis-related strings
        $redis1 = "6379"  // Redis default portu
        $redis2 = "redis" nocase
        $redis3 = "REDIS" 
        $redis4 = "127.0.0.1:6379"
        
        // C2 Communication ports
        $port_https = "443"
        $port_http = "80"

        // Additional RediShell indicators
        $shell1 = "/bin/sh" nocase
        $shell2 = "/bin/bash" nocase
        $shell3 = "cmd.exe" nocase
        $shell4 = "powershell" nocase
        $shell5 = "cmd" nocase
        
        // ARP (Address Resolution Protocol)
        $mac1 = "FF:FF:FF:FF:FF:FF" fullword
        $ether_type = "0x0806" nocase


    condition:
        // Senaryo 1: Doğrudan C2 altyapısı
        (any of ($ip*) or any of ($dom*)) or
        
        // Senaryo 2: POST method + C2 altyapısı
        ((any of ($method*) or $post_obfuscated) and (any of ($ip*) or any of ($dom*))) or
        
        // Senaryo 3: Sleep behavior + PE dosyası (executable)
        ((any of ($sleep*) or $sleep_obfuscated) and filesize < 8MB and pe.is_pe) or

        // Senaryo 4: Redis + C2 kombinasyonu
        (any of ($redis*) and (any of ($ip*) or any of ($dom*))) or

        // Senaryo 5: Shell komutları + C2
        (any of ($shell*) and (any of ($ip*) or any of ($dom*))) or

        // Senaryo 6: Yüksek risk kombinasyonu
        (any of ($redis*) and any of ($shell*) and filesize < 5MB) or

        // Senaryo 7: ARP risk kombinasyonu
        (any of ($mac1) and ($ether_type)) or

        // Senaryo 8: Port risk kombinasyonu
        (any of ($port_https) and ($port_http))
}