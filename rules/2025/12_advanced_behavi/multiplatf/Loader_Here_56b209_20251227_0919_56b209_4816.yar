rule Loader_Here_56b209 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for loader: AI is upending file security. Here’s how to fight back"
        reference = "https://www.reversinglabs.com/blog/ai-file-security-fight-back"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 88
        mitre_techniques = "T1105, T1566, T1071, T1132, T1573"
        behaviors = "Code Signing Abuse"
        source = "ReversingLabs Blog"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse T1105, T1566, T1071
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            