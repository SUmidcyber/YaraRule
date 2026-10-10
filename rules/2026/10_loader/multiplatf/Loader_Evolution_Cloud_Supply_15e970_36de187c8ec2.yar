rule Loader_Evolution_Cloud_Supply_15e970 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-10"
        description = "Detection for loader: Evolution of Web3 in Cloud Supply Chain Attacks"
        reference = "https://unit42.paloaltonetworks.com/web3-cloud-supply-chain-attacks/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 88
        source = "Unit 42"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "opensourcemalware.com" nocase
        $domain2 = "ransom-isac.org" nocase

    condition:
        (any of ($domain*)) and filesize < 10MB
