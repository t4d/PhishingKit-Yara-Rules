rule PK_Ionos_keyword : Ionos
{
    meta:
        description = "Phishing Kit impersonating Ionos"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-05"
        comment = "Phishing Kit - Ionos - 'From: KEYWORD'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Webmail_files"
        $spec_dir2 = "robots_data"
        $spec_file1 = "Login.php"
        $spec_file2 = "mailbox.system.php"
        $spec_file3 = "Webmail.htm"
        $spec_file4 = "ionos.min.css"
        $spec_file5 = "zones.js"
        $spec_file6 = "email-marketing.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
