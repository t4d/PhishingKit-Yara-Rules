rule PK_Boursorama_xoxo : Boursorama
{
    meta:
        description = "Phishing Kit impersonating Boursorama"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-16"
        comment = "Phishing kit - Boursorama - 'boursorama log By XoXo'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "connexion"
        $spec_dir1 = "bundles"
        // specific file found in PhishingKit
        $spec_file = "boursorama-banque-logo@2x.png"
        $spec_file2 = "snd4.php"
        $spec_file3 = "otp2.php"
        $spec_file4 = "fin.php"
        $spec_file5 = "DSP2_actu_Covid19.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}