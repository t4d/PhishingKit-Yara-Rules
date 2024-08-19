rule PK_Colissimo_blackforce : Colissimo
{
    meta:
        description = "Phishing Kit impersonating Colissimo"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-09"
        comment = "Phishing Kit - Colissimo - 'Coded By Root_Dr'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "config"
        $spec_dir2 = "prevents"
        $spec_dir3 = "botActBan"
        // specific files found in PhishingKit
        $spec_file = "infoz.php"
        $spec_file1 = "stats.ini"
        $spec_file2 = "processing.php"
        $spec_file3 = "picto1-envoyeruncolis-mars22.svg"
        $spec_file4 = "logo-colissimo.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
