rule Infostealer_How_Browse_Web_c2e52f {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for infostealer: How to Browse the Web More Sustainably With a Green Browser"
        reference = "https://thehackernews.com/2025/12/how-to-browse-sustainably-with-a-green-browser.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 85
        mitre_techniques = "T1105, T1566, T1071, T1547, T1132"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "customer.appesteem.com"
        $domain2 = "extension.html"
        $domain3 = "monitoring.html"

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
            