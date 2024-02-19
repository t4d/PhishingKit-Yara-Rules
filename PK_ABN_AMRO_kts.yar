rule PK_ABN_AMRO_kts : ABN_AMRO
{
    meta:
        description = "Phishing Kit impersonating ABN AMRO Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-11-29"
        comment = "Phishing Kit - ABN AMRO Bank - by kts"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "a1b2c3"
        $spec_dir2 = "code5"
        $spec_dir3 = "def-page"
        $spec_file = "php.php"
        $spec_file2 = "man.txt"
        $spec_file3 = "texts.json"
        $spec_file4 = "abnamro-button-3683dd96add3e002f24067465cf2ac2d.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
