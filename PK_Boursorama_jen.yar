rule PK_Boursorama_jen : Boursorama
{
    meta:
        description = "Phishing Kit impersonating Boursorama"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-26"
        comment = "Phishing kit - Boursorama - using a 'jen' named dir."

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "connexion"
        $spec_dir1 = "logs"
        // specific file found in PhishingKit
        $spec_file = "boursorama-banque-logo@2x.png"
        $spec_file2 = "carte.php"
        $spec_file3 = "go1.php"
        $spec_file4 = "netcraft_check.php"
        $spec_file5 = "authentification.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
