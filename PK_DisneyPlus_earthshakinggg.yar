rule PK_DisneyPlus_earthshakinggg : DisneyPlus
{
    meta:
        description = "Phishing Kit impersonating Disney Plus"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-08-17"
        comment = "Phishing Kit - DisneyPlus - 'Password Capture @earthshakinggg'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "action"
        $spec_dir2 = "ccs"
        $spec_dir3 = "panel"
        $spec_file1 = "verificationerror.php"
        $spec_file2 = "step6.php"
        $spec_file3 = "banlist.txt"
        $spec_file4 = "external_poller_sample.php"
        $spec_file5 = "data.db"
        $spec_file6 = "disney.min.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
