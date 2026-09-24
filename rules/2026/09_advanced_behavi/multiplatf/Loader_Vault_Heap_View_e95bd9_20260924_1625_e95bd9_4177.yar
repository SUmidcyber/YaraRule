rule Loader_Vault_Heap_View_e95bd9 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Advanced detection rule for loader: A Vault with a Heap-View: The Uncomfortable Space Between AgentCore Ha"
        reference = "https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 88
        mitre_techniques = "T1105, T1140, T1071, T1566, T1132"
        behaviors = "Screen Capture"
        source = "Unit 42"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "mastodon.social"
        $domain2 = "identity.html"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Screen Capture T1105, T1140, T1071
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            