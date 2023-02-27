rule PK_Santander_darkness : Santander
{
    meta:
        description = "Phishing Kit impersonating Santander"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-17"
        comment = "Phishing Kit - Santander - 'BY-DarkneSs'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "boots"
        $spec_dir2 = "style"
        $spec_dir3 = "js"
        $spec_file1 = "firma_electronica.php"
        $spec_file2 = "telegram.php"
        $spec_file3 = "TBLIGHcc.php"
        $spec_file4 = "Mi_cuenta.php"
        $spec_file5 = "ta3ajoub.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
