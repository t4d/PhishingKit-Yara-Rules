rule PK_BELL_medpage : BELL
{
    meta:
        description = "Phishing Kit impersonating BELL MTS service"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-04-08"
        comment = "Phishing Kit - BELL - 'Scampage by medpage'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "files"
        $spec_dir2 = "header_data"
        $spec_dir3 = "includes"
        $spec_file1 = "relogging.php"
        $spec_file2 = "One_Time.php"
        $spec_file3 = "bell.myBell.core.css"
        $spec_file4 = "722MIWu_TMZiQau3mAaarHtCk2pd6rTYw5oNsH4wR_g.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
