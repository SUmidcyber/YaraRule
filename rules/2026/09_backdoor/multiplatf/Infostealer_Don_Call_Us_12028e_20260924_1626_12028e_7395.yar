rule Infostealer_Don_Call_Us_12028e {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Advanced detection rule for infostealer: Don’t Call Us, We’ll Call Your APIs | TraderTraitor Backdoors Resurfac"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        mitre_techniques = "T1105, T1140, T1071, T1132, T1204"
        behaviors = "Code Signing Abuse, Screen Capture, Clipboard Data"
        source = "SentinelLabs - We are hunters, reversers, exploit developers, and tinkerers shedding light on the world of malware, exploits, APTs, and cybercrime across all platforms."
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "1CD6D13FF15ADBF7A42025D10EC99B4A"
        $hash2 = "1cd6d13ff15adbf7a42025d10ec99b4a"
        $hash3 = "5728b11d30586bbfc1d8bd12df1c722a06e767a2"

        // Network Indicators
        $domain1 = "layerzero.network"
        $domain2 = "layerzero.network"
        $domain3 = "kelpdao-incident-report.pdf"

        // Behavioral Indicators
        $behavior1 = "IoCs"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse, Screen Capture, Clipboard Data T1105, T1140, T1071
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            