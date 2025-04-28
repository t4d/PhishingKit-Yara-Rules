rule PK_Avida_zabi : Avida
{
    meta:
        description = "Phishing Kit impersonating Avida Finance"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-25"
        comment = "Phishing Kit - Avida - use '$zabi' variable name"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "api"
        $spec_dir2 = "mobil_fichiers"
        // specific file found in PhishingKit
        $spec_file = "accpt.htm"
        $spec_file2 = "mobil.htm"
        $spec_file3 = "perso.htm"
        $spec_file4 = "step4.php"
        $spec_file5 = "avida-logo.png"
    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        all of ($spec_file*)
}
