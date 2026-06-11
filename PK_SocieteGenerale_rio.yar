rule PK_SocieteGenerale_rio : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-10"
        comment = "Phishing Kit - Societe Generale - built to steal bank and RIO data"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "panel"
        $spec_dir1 = "graveyard"
        $spec_dir2 = "cdns"
        $spec_file1 = "newips.php"
        $spec_file2 = "get_statu.php"
        $spec_file3 = "inst2.php"
        $spec_file4 = "logo-sg-seul.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
