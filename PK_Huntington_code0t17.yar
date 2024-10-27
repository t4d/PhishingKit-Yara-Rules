rule PK_Huntington_code0t17 : Huntington
{
    meta:
        description = "Phishing Kit impersonating Huntington bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-30"
        comment = "Phishing Kit - Huntington Bank - '@CodeOt17'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "1Qkfvj6YSXouY-bJMQ"
        $spec_dir2 = "nuance"
        $spec_dir3 = "rol"
        $spec_file = "5EMTYiTls.html"
        $spec_file2 = "db_connectT.php"
        $spec_file3 = "verify.html"
        $spec_file4 = "nuanceChat.html"
        $spec_file5 = "background-960.jpg"
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        all of ($spec_file*)
}
