rule PK_TruityCU_prohqcker : TruityCU
{
    meta:
        description = "Phishing Kit impersonating TruityCU"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-03"
        comment = "Phishing Kit - TruityCU - 'Prohqcker_Bot*TCU'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "css"
        $spec_dir2 = "file"
        $spec_file1 = "personal.html"
        $spec_file2 = "db_connect3.php"
        $spec_file3 = "c.html"
        $spec_file4 = "224.css"
        $spec_file5 = "vthreeallFullCss.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
