rule PK_CashApp_blackhole : CashApp
{
    meta:
        description = "Phishing Kit impersonating Cash App"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2026-01-28"
        comment = "Phishing Kit - Cash App - 'Blackhole'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "auth"
        $spec_dir2 = "source"
        $spec_dir3 = "res"

        $spec_file0 = "botblocker.php"
        $spec_file1 = "hits.txt"
        $spec_file2 = "README.txt"
        $spec_file3 = "billing.php"
        $spec_file5 = "complete.php"
        $spec_file4 = "ccv.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
