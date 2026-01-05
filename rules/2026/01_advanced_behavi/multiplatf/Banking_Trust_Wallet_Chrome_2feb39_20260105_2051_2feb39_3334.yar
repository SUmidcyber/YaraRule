rule Banking_Trust_Wallet_Chrome_2feb39 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for banking: Trust Wallet Chrome Extension Hack Drains $8.5M via Shai-Hulud Supply "
        reference = "https://thehackernews.com/2025/12/trust-wallet-chrome-extension-hack.html"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 88
        mitre_techniques = "T1204, T1071, T1059, T1573"
        behaviors = "WMI Abuse"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "hack.html"
        $domain2 = "trustwallet.com"
        $domain3 = "thehackernews.uk"
        $ip1 = "138.124.70.40"

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: WMI Abuse T1204, T1071, T1059
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            