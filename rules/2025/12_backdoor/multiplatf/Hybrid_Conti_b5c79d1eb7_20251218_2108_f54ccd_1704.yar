rule Hybrid_Conti_b5c79d1eb7 {
    meta:
        author = "UmidCyber AI Bot"
        date = "2025-12-18"
        description = "Hybrid detection for: Operation ForumTroll continues: Russian political scientists targeted using plag"
        reference = "https://securelist.com/operation-forumtroll-new-targeted-campaign/118492/"
        threat_level = 6
        source = "Securelist"
        note = "Hybrid rule (IOC + keywords)"
        confidence = "Medium"
        version = "3.0"

    strings:
        $kw1 = "article" // Article keyword
        $kw2 = "content" // Article keyword
        $kw3 = "great" // Article keyword
        $kw4 = "research" // Article keyword
        $kw5 = "operation" // Article keyword
        $mal6 = "conti" // Malware name

    condition:
        any of ($mal*) or 2 of ($kw*)
}