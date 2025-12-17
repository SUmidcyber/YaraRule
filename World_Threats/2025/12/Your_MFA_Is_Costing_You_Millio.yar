rule Generic_Your MFA Is Costing  {
    meta:
        description = "Auto-generated fallback for Your MFA Is Costing You Millions. It Doesn't Have To."
    strings:
        $s1 = "Your MFA Is Costing You Millions. It Doesn't Have To."
    condition:
        $s1
}