rule PK_TaiwanPost_alfabrabus : TaiwanPost
{
    meta:
        description = "Phishing Kit impersonating Taiwan POST"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-22"
        comment = "Phishing Kit - Taiwan POST - 'By @ALFABRABUS'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "eradox"
        $spec_dir2 = "php"
        $spec_dir3 = "js"
        // specific file found in PhishingKit
        $spec_file = "send6.php"
        $spec_file2 = "serveur.php"
        $spec_file3 = "cart.php"
        $spec_file4 = "sms4.php"
        $spec_file5 = "PK_TaiwanPost_alfabrabus"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
