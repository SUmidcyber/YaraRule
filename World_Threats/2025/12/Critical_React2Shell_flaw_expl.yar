rule Generic_Critical React2Shell {
    meta:
        description = "Auto-generated fallback for Critical React2Shell flaw exploited in ransomware attacks"
    strings:
        $s1 = "Critical React2Shell flaw exploited in ransomware attacks"
    condition:
        $s1
}