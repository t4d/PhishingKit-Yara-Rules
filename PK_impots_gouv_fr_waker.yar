rule PK_impots_gouv_fr_waker : impots_gouv_fr
{
    meta:
        description = "Phishing Kit impersonating impots.gouv.fr"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-05"
        comment = "Phishing Kit - impots.gouv.fr - 'From: Waker <support@Apple.fr>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "app"
        $spec_dir1 = "server"
        $spec_dir2 = "cni"
        $spec_file1 = "back.php"
        $spec_file2 = "explication.php"
        $spec_file3 = "ab.php"
        $spec_file4 = "logo-fc.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
