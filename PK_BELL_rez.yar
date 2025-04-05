rule PK_BELL_rez : BELL
{
    meta:
        description = "Phishing Kit impersonating BELL MTS service"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-26"
        comment = "Phishing Kit - BELL"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "index_files"
        $spec_file1 = "mail.php"
        $spec_file2 = "index.htm"
        $spec_file3 = "base.js"
        $spec_file4 = "bellmts.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
