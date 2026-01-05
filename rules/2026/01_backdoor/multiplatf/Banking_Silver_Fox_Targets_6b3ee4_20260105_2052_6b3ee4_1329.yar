rule Banking_Silver_Fox_Targets_6b3ee4 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for banking: Silver Fox Targets Indian Users With Tax-Themed Emails Delivering Vall"
        reference = "https://thehackernews.com/2025/12/silver-fox-targets-indian-users-with.html"
        threat_level = 9
        malware_type = "banking"
        confidence_score = 91
        mitre_techniques = "T1059, T1547, T1566, T1071, T1204"
        behaviors = "Scheduled Task, Keylogging"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "exploits-microsoft-signed.html"
        $domain2 = "microsoft-teams.html"
        $domain3 = "levelblue.com"

        // Behavioral Indicators
        $behavior1 = "explorer.exe"

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Scheduled Task, Keylogging T1059, T1547, T1566
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            