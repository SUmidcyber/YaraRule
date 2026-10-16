rule Banking_Powered_Espionage_Campaign_3a4e84 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-16"
        description = "Detection for banking: AI-Powered Espionage Campaign Targets Government Linux Infrastructure"
        reference = "https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/"
        threat_level = 9
        malware_type = "banking"
        confidence_score = 95
        source = "Unit 42"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "b1e82c6b0caea177e8bb71ad826867f509c65f0a43a651b50253e7c726566eac"
        $hash2 = "1505a3a727f8899b2ad343519f7bf9c438b8b802f8d6b854f5db3b52f857c76a"
        $hash3 = "c527b94e3d21824a674face4cd9d862e536b60ccbf54573839e3360f99188343"
        $hash4 = "27d799ceadb570bfca890d4c2572314afe57eecf14083d30409da15afdfc4704"
        $hash5 = "2bf7992e6260c1a98c709fa98ec766fb9f27692f338b30b43ac821b824fd849e"

        // Files
        $file1 = "Updater.exe" nocase

    condition:
        ( any of ($hash*) and any of ($file*) )
