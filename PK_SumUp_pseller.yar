rule PK_SumUp_pseller : SumUp
{
    meta:
        description = "Phishing Kit impersonating SumUp"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-08"
        comment = "Phishing Kit - SumUp - '@ICQ : @pseller200'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "mucha"
        $spec_dir2 = "req"
        $spec_file1 = "index-e.php"
        $spec_file2 = "otp-e.php"
        $spec_file3 = "funcs.php"
        $spec_file4 = "wait-e.php"
        $spec_file5 = "be5f86847460dc4e.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
