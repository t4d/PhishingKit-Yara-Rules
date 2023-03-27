rule PK_ANTAI_waker : ANTAI
{
    meta:
        description = "Phishing Kit impersonating French Agence nationale de traitement automatise des infractions"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-20"
        comment = "Phishing Kit - ANTAI - 'Waker Amende REZ'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "server"
        $spec_dir2 = "app"

        $spec_file1 = "back.php"
        $spec_file2 = "ab.php"
        $spec_file3 = "config.php"
        $spec_file4 = "5.php"
        $spec_file5 = "logo-amendes-gouv.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
