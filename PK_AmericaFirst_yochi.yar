rule PK_AmericaFirst_yochi : AmericaFirst
{
    meta:
        description = "Phishing Kit impersonating America First Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-25"
        comment = "Phishing Kit - America First - 'SCAM PAGE AFCU BANK #By YOCHI'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "req"
        $spec_dir1 = "afu"
        $spec_file1 = "yo.txt"
        $spec_file2 = "settings.php"
        $spec_file3 = "cardproc.php"
        $spec_file4 = "basicbot.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
