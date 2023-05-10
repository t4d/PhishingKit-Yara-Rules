rule PK_Galicia_officenest : Galicia
{
    meta:
        description = "Phishing Kit impersonating Galicia online banking"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-10"
        comment = "Phishing Kit - Galicia - officenestBot, name of the Telegram bot used"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        $spec_dir2 = "fonts"
        // specific file found in PhishingKit
        $spec_file = "configGA.php"
        $spec_file2 = "login4.php"
        $spec_file3 = "asdasffbgfbgdrhryjutipikhjghjhtdgrfgddfgdgfngbgfghtyjuouiytrtfsddddddddddddddkdbhflhsbfkwbroewniflkf.html"
        $spec_file4 = "config.php"
        $spec_file5 = "wink2.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
