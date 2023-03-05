rule PK_CA_einstein : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-27"
        comment = "Phishing Kit - Credit Agricole - 'Einstein REZ'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "param"
        $spec_dir2 = "anti__boot"
        $spec_file1 = "securicode.php"
        $spec_file2 = "pay.php"
        $spec_file3 = "SendApi.php"
        $spec_file4 = "Logo_Natio_Entreprise_CA-seul.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
