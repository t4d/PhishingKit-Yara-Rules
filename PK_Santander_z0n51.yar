rule PK_Santander_z0n51 : Santander
{
    meta:
        description = "Phishing Kit impersonating Santander"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-19"
        comment = "Phishing Kit - Santander - 'z0n51'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "inc"
        $spec_dir2 = "z0n51"
        $spec_dir3 = "vendor"
        $spec_file1 = "firma.php"
        $spec_file2 = "vu.php"
        $spec_file3 = "sofia.png"
        $spec_file4 = "secure-asterisk.svg"
        $spec_file5 = "logoo.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
