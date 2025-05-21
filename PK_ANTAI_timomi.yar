rule PK_ANTAI_timomi : ANTAI
{
    meta:
        description = "Phishing Kit impersonating French ANTAI (amendes) portal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-14"
        comment = "Phishing Kit - ANTAI - contains directory named 'timomi'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "service"
        $spec_dir2 = "timomi"
        $spec_file1 = "verif.php"
        $spec_file2 = "session.php"
        $spec_file3 = "snipped.css"
        $spec_file4 = "logo-amendes-gouv.svg"
        $spec_file5 = "marianne-regular.woff"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
