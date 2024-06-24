rule PK_SocieteGenerale_prestoworld : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-06-16"
        comment = "Phishing Kit - Societe Generale - 'AUTHOR :  PRESTOWORLD'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "app"
        $spec_dir1 = "panel"
        $spec_dir2 = "bots"
        $spec_file1 = "tan.php"
        $spec_file2 = "out.php"
        $spec_file3 = "ctr.php"
        $spec_file4 = "f5c285aaa3e40afa9d2093a8a38670ab.png"
        $spec_file5 = "logo-sg-muet.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
