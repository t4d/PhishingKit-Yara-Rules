rule PK_Viseca_fck : Viseca
{
    meta:
        description = "Phishing Kit impersonating Viseca one Digital Service"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-01"
        comment = "Phishing Kit - Viseca - use a 'fucked' named directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "fucked"
        $spec_dir2 = "image"
        $spec_file1 = "payment.php"
        $spec_file2 = "sms-error.php"
        $spec_file3 = "test.css"
        $spec_file4 = "one-small.svg"
        $spec_file5 = "menu.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
