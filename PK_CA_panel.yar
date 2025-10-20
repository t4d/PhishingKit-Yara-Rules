rule PK_CA_panel : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-10-04"
        comment = "Phishing Kit - Credit Agricole - with panel to interact with victim"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "app"
        $spec_dir2 = "panel"
        $spec_dir3 = "rzlt"
        $spec_file1 = "carte.php"
        $spec_file2 = "banned-ip.php"
        $spec_file5 = "email-error.php"
        $spec_file3 = "ZDG_MaBanque_092022.jpg"
        $spec_file4 = "logo_CAAP_216x40.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
