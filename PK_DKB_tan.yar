rule PK_DKB_tan : DKB
{
    meta:
        description = "Phishing Kit impersonating Das kann Bank (DKB)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-22"
        comment = "Phishing Kit - DKB - 'Page identifiant DKB tan'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "data"
        $spec_dir2 = "style"
        $spec_file1 = "merci.php"
        $spec_file2 = "verification-setep.php"
        $spec_file3 = "class-wordpres-api.php"
        $spec_file4 = "identifiant.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
