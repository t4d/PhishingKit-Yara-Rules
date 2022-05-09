rule PK_AOL_cross : AOL
{
    meta:
        description = "Phishing Kit impersonating AOL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-04"
        comment = "Phishing Kit - AOL - '- Created By Cross Hacker -'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "log.php"
        $spec_file2 = "login.php"
        $spec_file3 = "aolpass.html"
        $spec_file4 = "aoluser.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}