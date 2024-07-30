rule PK_GarantiBBVA_Turkey : GarantiBBVA
{
    meta:
        description = "Phishing Kit impersonating Garanti BBVA Turkey"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-30"
        comment = "Phishing Kit - GarantiBBVA - 'Garanti BBVA Turkey'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "home"
        $spec_file1 = "pin.php"
        $spec_file2 = "spin.html"
        $spec_file3 = "email.html"
        $spec_file4 = "code.html"
        $spec_file5 = "sms.php"
        $spec_file6 = "pin.html"
        $spec_file7 = "info.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
