rule PK_Ionos_02d0 : Ionos
{
    meta:
        description = "Phishing Kit impersonating Ionos webmail"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-08"
        comment = "Phishing Kit - Ionos - contain files named *02d0.js"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "source"
        $spec_dir2 = "img"
        $spec_file1 = "ionos.min02d0.js"
        $spec_file2 = "main.min02d0.js"
        $spec_file3 = "validate.php"
        $spec_file4 = "ionos.min.css"
        $spec_file5 = "splashscreen_1096.oYJ4s4eRSIbPMqWPptiGc"
        $spec_file6 = "my-ionos.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
