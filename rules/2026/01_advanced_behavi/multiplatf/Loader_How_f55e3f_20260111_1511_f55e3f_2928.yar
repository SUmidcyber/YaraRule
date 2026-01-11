rule Loader_How_f55e3f {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for loader: How supply chain risk can affect cyber insurance"
        reference = "https://www.reversinglabs.com/blog/supply-chain-risk-insurance"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 80
        mitre_techniques = "T1071, T1573, T1105"
        behaviors = "N/A"
        source = "ReversingLabs Blog"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "investments-in-2026.html"
        $domain2 = "woodruffsawyer.com"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1071, T1573, T1105
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            