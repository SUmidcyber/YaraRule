rule Loader_Korean_Air_316811 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-29"
        description = "Advanced detection rule for loader: Korean Air data breach exposes data of thousands of employees"
        reference = "https://www.bleepingcomputer.com/news/security/korean-air-data-breach-exposes-data-of-thousands-of-employees/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 85
        mitre_techniques = "T1566, T1105, T1573, T1071"
        behaviors = "N/A"
        source = "BleepingComputer"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "koreajoongangdaily.joins.com"
        $domain2 = "koreajoongangdaily.joins.com"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1566, T1105, T1573
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            