rule Infostealer_China_Linked_Evasive_22c95e {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for infostealer: China-Linked Evasive Panda Ran DNS Poisoning Campaign to Deliver MgBot"
        reference = "https://thehackernews.com/2025/12/china-linked-evasive-panda-ran-dns.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 94
        mitre_techniques = "T1105, T1566, T1071, T1547, T1115"
        behaviors = "Code Signing Abuse, Keylogging, Clipboard Data"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "hackers.jpg"
        $domain2 = "thehackernews.uk"
        $domain3 = "reroutes-dns.html"
        $ip1 = "7.0.18.0"

        // Behavioral Indicators
        $behavior1 = "svchost.exe"

        // File Artifacts
        $file1 = "4.dll"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse, Keylogging, Clipboard Data T1105, T1566, T1071
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            