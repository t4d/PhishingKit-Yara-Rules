rule PK_CA_antibomb : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-08"
        comment = "Phishing Kit - Credit Agricole - using AntiBomb filter"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "data"
        $spec_dir2 = "logs"
        $spec_dir3 = "layouts"

        $spec_file0 = "pending2.php"
        $spec_file1 = "to.php"
        $spec_file2 = "request.php"
        $spec_file3 = "femme-transat-tablette.jpg"
        $spec_file4 = "CA_Logo_seul-1.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
