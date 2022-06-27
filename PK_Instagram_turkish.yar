rule PK_Instagram_turkish : Instagram
{
    meta:
        description = "Phishing Kit impersonating Instagram"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-24"
        comment = "Phishing Kit - Instagram - using turkish comments"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_file1 = "load.php"
        $spec_file2 = "username.php"
        $spec_file3 = "repassword.php"
        $spec_file4 = "2fac.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}