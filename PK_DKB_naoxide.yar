rule PK_DKB_naoxide : DKB
{
    meta:
        description = "Phishing Kit impersonating Das kann Bank (DKB)"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-08-29"
        comment = "Phishing Kit - DKB - 'nAoxide-DBK-Card info'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "loading2.html"
        $spec_file2 = "step4.php"
        $spec_file3 = "kreditKarte.html"
        $spec_file4 = "thanks.png"
        $spec_file5 = "config.php"
        $spec_file6 = "thankyou.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}
