rule PK_DKB_boom : DKB
{
    meta:
        description = "Phishing Kit impersonating Das kann Bank (DKB)"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-12"
        comment = "Phishing Kit - DKB - 'function boom($message)'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "bot"
        $spec_dir2 = "BOTS"
        $spec_file1 = "smsdkb.php"
        $spec_file2 = "Loginfirst.php"
        $spec_file3 = "kreditKarte.html"
        $spec_file4 = "Karte.php"
        $spec_file5 = "blocker.php"
        $spec_file6 = "8.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
