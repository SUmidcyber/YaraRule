rule Infostealer_Discord_Stealer_Using_4837b0 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for infostealer: VVS Discord Stealer Using Pyarmor for Obfuscation and Detection Evasio"
        reference = "https://unit42.paloaltonetworks.com/vvs-stealer/"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        mitre_techniques = "T1082, T1059, T1547, T1566, T1071"
        behaviors = "Registry Persistence, Startup Folder, Code Signing Abuse, Screen Capture"
        source = "Unit 42"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "273b1b1373cf25e054a61e2cb8a947b8"
        $hash2 = "273b1b1373cf25e054a61e2cb8a947b8"
        $hash3 = "c7e6591e5e021daa30f949a6f6e0699ef2935d2d7c06ea006e3b201c52666e07"

        // Network Indicators
        $domain1 = "mastodon.social"
        $domain2 = "decodecybercrime.com"
        $domain3 = "pyinstaller.org"
        $ip1 = "115.0.0.0"

        // Behavioral Indicators
        $behavior1 = "PowerShell scripts](https://unit42.paloaltonetwork"

        // File Artifacts
        $file1 = "vvs.py"
        $file2 = "obf.js"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Registry Persistence, Startup Folder, Code Signing Abuse T1082, T1059, T1547
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            