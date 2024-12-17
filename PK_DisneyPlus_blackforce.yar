rule PK_DisneyPlus_blackforce : DisneyPlus
{
    meta:
        description = "Phishing Kit impersonating Disney Plus"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-12-16"
        comment = "Phishing Kit - DisneyPlus - 'function boom($message)'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "help"
        $spec_dir2 = "home"
        $spec_dir3 = "action"
        $spec_file1 = "isps.json"
        $spec_file2 = "printbot.php"
        $spec_file3 = "protection.php"
        $spec_file4 = "base.php"
        $spec_file5 = "9.php"
        $spec_file6 = "disney.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
