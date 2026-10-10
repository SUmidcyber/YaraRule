rule Infostealer_Attackers_Hijack_Registries_058c92 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-10"
        description = "Detection for infostealer: Attackers Hijack .gh, .sl, and .as Registries to Obtain Certificates f"
        reference = "https://thehackernews.com/2026/10/attackers-hijack-gh-sl-and-as.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "8886ca2b71501a6729f1ae868bd7d7b9b53c5cb6b5c7d851d041db4d6206945d"
        $hash2 = "b7ea8c77695cf9791a9d45f17c33ebb9bd5f68d4c96df6f56136dc6a834576d2"
        $hash3 = "0357032e1214ae11d7da8e00f6b89fb7694e240b17d05f2f47feaf43e96aa7d8"
        $hash4 = "5b7c491c8784eb438b1634981f1ea6333d3557431268233c2a7a92173ca17122"
        $hash5 = "491f453d208bbb7923626c208df93c95fdfae3b78b738b996c8dafda9d00619a"

        // Domains
        $domain1 = "thehackernews.uk" nocase

    condition:
        ( any of ($hash*) and any of ($domain*) )
