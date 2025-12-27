rule Loader_From_Webrat_92d05f {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for loader: From cheats to exploits: Webrat spreading via GitHub"
        reference = "https://securelist.com/webrat-distributed-via-github/118555/"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 91
        mitre_techniques = "T1123, T1105, T1566, T1071, T1125"
        behaviors = "AV/EDR Disabling, Keylogging"
        source = "Securelist"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "61b1fc6ab327e6d3ff5fd3e82b430315"
        $hash2 = "28a741e9fcd57bd607255d3a4690c82f"
        $hash3 = "28a741e9fcd57bd607255d3a4690c82f"

        // Network Indicators
        $domain1 = "cybersecurefox.com"
        $domain2 = "Webrat1.png"
        $domain3 = "Webrat2.png"

        // File Artifacts
        $file1 = "payload.dll"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: AV/EDR Disabling, Keylogging T1123, T1105, T1566
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            