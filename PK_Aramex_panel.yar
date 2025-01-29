rule PK_Aramex_panel : Aramex
{
    meta:
        description = "Phishing Kit impersonating Aramex"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-25"
        comment = "Phishing Kit - Aramex phishing kit with panel"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "txt"
        $spec_dir2 = "system"
        $spec_file0 = "pickupcc.php"
        $spec_file1 = "3dsecure.php"
        $spec_file2 = "confirme.php"
        $spec_file3 = "aramex-logo.svg"
        $spec_file4 = "ar.ico"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
