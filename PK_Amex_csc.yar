rule PK_Amex_csc : Amex
{
    meta:
        description = "Phishing Kit impersonating American Express"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-28"
        comment = "Phishing Kit - Amex - 'verfy Card Security Code'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "account"
        $spec_dir2 = "bots"
        $spec_file1 = "ultimate_blocker.php"
        $spec_file2 = "visit.php"
        $spec_file3 = "final_submit.php"
        $spec_file4 = "csc_verify.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
