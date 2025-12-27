rule Infostealer_Fake_Package_Steals_759662 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for infostealer: Fake WhatsApp API Package on npm Steals Messages, Contacts, and Login "
        reference = "https://thehackernews.com/2025/12/fake-whatsapp-api-package-on-npm-steals.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 85
        mitre_techniques = "T1105, T1566, T1071, T1547, T1060"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "whatsapp-api.jpg"
        $domain2 = "thehackernews.uk"
        $domain3 = "bybitapi.net"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1105, T1566, T1071
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            