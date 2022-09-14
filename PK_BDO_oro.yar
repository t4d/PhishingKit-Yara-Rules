rule PK_BDO_oro : BDO
{
    meta:
        description = "Phishing Kit impersonating BDO Unibank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-27"
        comment = "Phishing Kit - BDO - '-[Banco De Oro 2020]-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "T3R"
        $spec_dir2 = "sso"
        $spec_file1 = "mobilenumber.php"
        $spec_file2 = "otp3.php"
        $spec_file3 = "usera.php"
        $spec_file4 = "logs.html"
        $spec_file5 = "bdo-logo.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
