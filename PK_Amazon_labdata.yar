rule PK_Amazon_labdata : Amazon
{
    meta:
        description = "Phishing Kit impersonating Amazon"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-27"
        comment = "Phishing Kit - Amazon - 'Contact if you need help ICQ @labdata'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "bots"
        $spec_dir1 = "mobile"
        $spec_file1 = "ref.php"
        $spec_file2 = "password.php"
        $spec_file3 = "billing.php"
        $spec_file4 = "new-nav-sprite-global-1x_blueheaven-account.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
