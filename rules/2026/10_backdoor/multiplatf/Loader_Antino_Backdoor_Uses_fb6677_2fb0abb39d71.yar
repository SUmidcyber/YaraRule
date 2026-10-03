rule Loader_Antino_Backdoor_Uses_fb6677 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-03"
        description = "Detection for loader: Antino Backdoor Uses Outlook and OneDrive for C2 in China-Nexus Espion"
        reference = "https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "d32tpl7xt7175h.cloudfront" nocase
        $domain2 = "thehackernews.uk" nocase

        // Files
        $file1 = "slc.dll" nocase
        $file2 = "cmd.exe" nocase

        // Behavioral
        $behavior1 = "cmd.exe" nocase

    condition:
        (2 of ($domain*, $behavior*, $file*)) and filesize < 10MB
