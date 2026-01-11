rule Loader_From_Hypothesis_Action_f9e05c {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for loader: From Hypothesis to Action: Proactive Threat Hunting with Elastic Secur"
        reference = "https://www.elastic.co/security-labs/proactive-threat-hunting-with-elastic-security"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1573, T1204, T1071, T1547, T1218"
        behaviors = "N/A"
        source = "Elastic Security Labs"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Behavioral Indicators
        $behavior1 = "import a query into an operational detection rule,"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1573, T1204, T1071
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            