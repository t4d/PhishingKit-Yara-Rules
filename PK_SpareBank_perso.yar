rule PK_SpareBank_perso : SpareBank
{
    meta:
        description = "Phishing Kit impersonating SpareBank1"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-02-15"
        comment = "Phishing Kit - SpareBank - using 'perso.php' file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "BankID_fichiers"
        $spec_dir2 = "fichier"
        // specific file found in PhishingKit
        $spec_file = "egan.php"
        $spec_file2 = "a_002.html"
        $spec_file3 = "perso.php"
        $spec_file4 = "SPOL.OL-2ed6562c.png"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
