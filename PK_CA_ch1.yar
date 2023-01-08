rule PK_CA_ch1 : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-08"
        comment = "Phishing Kit - Credit Agricole - 'From: [CH1_CA **]<info@CH1.com>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_dir2 = "sass"
        $spec_dir3 = "ses"

        $spec_file0 = "info.php"
        $spec_file1 = "password.php"
        $spec_file2 = "SendInfo.php"
        $spec_file3 = "region.php"
        $spec_file4 = "tasklist.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
