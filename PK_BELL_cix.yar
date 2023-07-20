rule PK_BELL_cix : BELL
{
    meta:
        description = "Phishing Kit impersonating BELL MTS service"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-18"
        comment = "Phishing Kit - BELL - 'cix Log User<users@cix>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "in_files"
        $spec_file1 = "h.html"
        $spec_file2 = "in.html"
        $spec_file3 = "ntesdoor.php"
        $spec_file4 = "bellmts.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
