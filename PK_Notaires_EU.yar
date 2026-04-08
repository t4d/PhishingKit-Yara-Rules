rule PK_Notaries_EU : Notaries
{
    meta:
        description = "Phishing Kit impersonating Notaires/Notaries From EU"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-04-05"
        comment = "Phishing Kit - Notaires"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "assets"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "check_logos.php"
        $spec_file2 = "connexion.php"
        $spec_file3 = "lt-inbox.png"
        $spec_file4 = "notaires-belgique.png"
        $spec_file5 = "notaires-lituanie.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
