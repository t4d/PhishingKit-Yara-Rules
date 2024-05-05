rule PK_Viseca_ghayt : Viseca
{
    meta:
        description = "Phishing Kit impersonating Viseca one Digital Service"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-11"
        comment = "Phishing Kit - Viseca - 'ghayt_Zone'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "anti__boot"
        $spec_dir2 = "js"
        $spec_file1 = "sms-login.php"
        $spec_file2 = "test.css"
        $spec_file3 = "visitors.html"
        $spec_file4 = "one-small.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
