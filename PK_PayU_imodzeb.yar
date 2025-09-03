rule PK_PayU_imodzeb : PayU
{
    meta:
        description = "Phishing Kit impersonating PayU"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-08-28"
        comment = "Phishing Kit - PayU - '- @Imodzeb -'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "packeges"
        $spec_dir2 = "img"
        $spec_file1 = "configuration.php"
        $spec_file2 = "sendsms2.php"
        $spec_file3 = "waiting.php"
        $spec_file4 = "waiting.css"
        $spec_file5 = "smserror.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
