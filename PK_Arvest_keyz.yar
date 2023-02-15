rule PK_Arvest_keyz : Arvest_Bank
{
    meta:
        description = "Phishing Kit impersonating Arvest bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-12"
        comment = "Phishing Kit - Arvest bank - arvest_keyzs_telegram"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "actions"
        $spec_dir2 = "configuration"
        $spec_file0 = "iii.php"
        $spec_file1 = "report_login.php"
        $spec_file2 = "tractor.jpg"
        $spec_file3 = "question.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
