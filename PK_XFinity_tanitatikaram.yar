rule PK_XFinity_tanitatikaram : XFinity
{
    meta:
        description = "Phishing Kit impersonating XFinity/Comcast"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-02-18"
        comment = "Phishing Kit - XFinity - use $tanitatikaram variable"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Logs"
        $spec_dir2 = "validation"

        $spec_file1 = "xfinitybrown-regular.woff2"
        $spec_file2 = "temp.txt"
        $spec_file3 = "session_account.php"
        $spec_file4 = "verify_session_reaccount.php"
        $spec_file5 = "xfinity-logo-grey.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
