rule PK_Ionos_oreoo : Ionos
{
    meta:
        description = "Phishing Kit impersonating Ionos"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-10"
        comment = "Phishing Kit - Ionos - 'From: Unknown <support@oreoo.com>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "send"
        $spec_dir2 = "libraries"
        $spec_file1 = "auth.php"
        $spec_file2 = "email-marketing.svg"
        $spec_file3 = "B_6.php"
        $spec_file4 = "ionos.min.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
