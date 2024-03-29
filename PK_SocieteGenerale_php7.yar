rule PK_SocieteGenerale_php7 : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-15"
        comment = "Phishing Kit - Societe Generale - contains .php7 files extension"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "app"
        $spec_dir1 = "panel"
        $spec_dir2 = "bots"
        $spec_file1 = "md.php7"
        $spec_file2 = "father.php7"
        $spec_file3 = "ctr.php7"
        $spec_file4 = "f5c285aaa3e40afa9d2093a8a38670ab.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
