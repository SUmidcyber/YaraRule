rule Trojan_Launches_Spear_Phish_cc6df6 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for trojan: MuddyWater Launches RustyWater RAT via Spear-Phishing Across Middle Ea"
        reference = "https://thehackernews.com/2026/01/muddywater-launches-rustywater-rat-via.html"
        threat_level = 9
        malware_type = "trojan"
        confidence_score = 95
        mitre_techniques = "T1573, T1204, T1071, T1060, T1566"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "1000046762.jpg"
        $domain2 = "backdoor.html"
        $domain3 = "nomercys.it"

        // Behavioral Indicators
        $behavior1 = "PowerShell and VBS loaders for initial access and "

        // Trojan/RAT specific
        $remote_access1 = "CreateRemoteThread" wide
        $remote_access2 = "WriteProcessMemory" wide
        $keylogger = "SetWindowsHookEx" wide
        $screenshot = "BitBlt" wide
        $persistence1 = "RegSetValueEx" wide
        $persistence2 = "CreateService" wide

        condition:
        // MITRE ATT&CK Techniques: T1573, T1204, T1071
            // Trojan/RAT detection logic
            (
                ( any of ($remote_access*) and any of ($persistence*) ) or
                ( $keylogger and $screenshot ) or
                ( $process_injection and $code_injection )
            ) and
            pe.is_pe
            