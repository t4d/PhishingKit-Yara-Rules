rule PK_LeBonCoin_abou : LeBonCoin
{
    meta:
        description = "Phishing Kit impersonating Le Bon Coin"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-25"
        comment = "Phishing Kit - LeBonCoin - 'saved from url=(0071)file:///C:/Users/jam/Desktop/abou-boncoin/leboncoin%20-%20connexion.htm'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Confirmez-votre-adresse_fichiers"
        $spec_dir2 = "Félicitation_fichiers"
        // specific file found in PhishingKit
        $spec_file = "Confirmez-votre-adresse.htm"
        $spec_file2 = "leboncoin-connexion.html"
        $spec_file3 = "hh.png"
        $spec_file4 = "lbc-front-web-logo.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
