rule Loader_Inside_Modern_Defending_981027 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Advanced detection rule for loader: Inside the Modern SOC: Defending the Cross-Environment Pivot"
        reference = "https://unit42.paloaltonetworks.com/soc-cross-environment-pivot/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 85
        mitre_techniques = "T1105, T1071, T1566, T1204, T1573"
        behaviors = "N/A"
        source = "Unit 42"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "mastodon.social"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1105, T1071, T1566
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            