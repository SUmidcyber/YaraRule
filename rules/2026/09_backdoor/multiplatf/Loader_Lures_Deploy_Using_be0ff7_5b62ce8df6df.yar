rule Loader_Lures_Deploy_Using_be0ff7 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Detection for loader: ClickFix Lures Deploy ChainScript RAT Using Polygon to Rotate C2 Infra"
        reference = "https://thehackernews.com/2026/09/clickfix-lures-deploy-chainscript-rat.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "blackpointcyber.com" nocase
        $domain2 = "ComponentTask33-4d14e6ac.msi" nocase
        $domain3 = "www.malwarebytes.com" nocase
        $domain4 = "pushsecurity.com" nocase
        $domain5 = "thehackernews.uk" nocase

        // Behavioral
        $behavior1 = "msiexec.exe" nocase

    condition:
        (( any of ($domain*) and any of ($behavior*) )) and filesize < 10MB
