rule PK_DHL_x911_2 : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-22"
        comment = "Phishing Kit - DHL - 'by https://t.me/X911_tools'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "X911"
        $spec_dir2 = "LBRAD"
        $spec_dir3 = "siftA"
        $spec_file1 = "E.php"
        $spec_file2 = "X_911.php"
        $spec_file3 = "Loa.php"
        $spec_file4 = "TELEGRMAT.php"
        $spec_file5 = "dhl-logo.svg"
        
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
