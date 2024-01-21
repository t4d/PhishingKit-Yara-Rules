rule PK_CA_tche : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-12"
        comment = "Phishing Kit - Credit Agricole - 'From: TCHE-Dev'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Show_system"
        $spec_dir2 = "config"
        $spec_dir3 = "Select"

        $spec_file0 = "Select_smsbenef.php"
        $spec_file1 = "authb.php"
        $spec_file2 = "data_reg.php"
        $spec_file3 = "sms.js"
        $spec_file4 = "question2.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
