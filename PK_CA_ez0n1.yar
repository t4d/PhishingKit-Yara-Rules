rule PK_CA_ez0n1 : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-12-29"
        comment = "Phishing Kit - Credit Agricole - using ez0n1 directory (z0n51 based)"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "ez0n1"
        $spec_file1 = "submit-old.php"
        $spec_file2 = "particuliers.jpg"
        $spec_file3 = "authfort.php"
        $spec_file4 = "securepass.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
