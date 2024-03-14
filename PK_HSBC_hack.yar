rule PK_HSBC_hack : HSBC
{
    meta:
        description = "Phishing Kit impersonating HSBC"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-22"
        comment = "Phishing Kit - HSBC - 'Made by Hack A++'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "admin"
        $spec_dir2 = "sounds"
        $spec_file1 = "dob-verification.php"
        $spec_file2 = "loginRE.php"
        $spec_file3 = "process.php"
        $spec_file4 = "logoTrans.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
