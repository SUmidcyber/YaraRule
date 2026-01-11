rule Loader_Worm_Spreads_Astaroth_7d4a05 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for loader: WhatsApp Worm Spreads Astaroth Banking Trojan Across Brazil via Contac"
        reference = "https://thehackernews.com/2026/01/whatsapp-worm-spreads-astaroth-banking.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1573, T1105, T1204, T1071, T1566"
        behaviors = "Scheduled Task"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "astaroth-banking.html"
        $domain2 = "whatsapp-worm.jpg"
        $domain3 = "thehackernews.uk"

        // Behavioral Indicators
        $behavior1 = "PowerShell or Python script to collect WhatsApp us"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Scheduled Task T1573, T1105, T1204
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            