rule PK_AOL_med : AOL
{
    meta:
        description = "Phishing Kit impersonating AOL"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-10-02"
        comment = "Phishing Kit - AOL - 'created by medpage'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir= "includes"
        $spec_file1 = "CONTROLS.php"
        $spec_file2 = "logging.php"
        $spec_file3 = "session_protect.php"
        $spec_file4 = "blacklist_lookup.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
