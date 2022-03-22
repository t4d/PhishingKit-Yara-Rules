rule PK_LinkedIn_freshtools : LinkedIn
{
    meta:
        description = "Phishing Kit impersonating LinkedIn"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-12"
        comment = "Phishing Kit - LinkedIn - 'FRESH [SPAM] TOOLS'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "LinkedIn Login, Sign in LinkedIn_files"
        $spec_file1 = "LinkedIn Login, Sign in LinkedIn-confim.htm"
        $spec_file2 = "dest5.htm"
        $spec_file3 = "post3.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
