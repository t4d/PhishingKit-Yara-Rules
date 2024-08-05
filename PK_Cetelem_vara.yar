rule PK_Cetelem_vara : Cetelem
{
    meta:
        description = "Phishing Kit impersonating Cetelem"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-05"
        comment = "Phishing Kit - Cetelem - 'From: <vara@gmail.com>"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "actions"
        $spec_dir2 = "common"
        $spec_dir3 = "prevents"
        // specific files found in PhishingKit
        $spec_file = "succes.php"
        $spec_file2 = "info_cli1.php"
        $spec_file3 = "rio.php"
        $spec_file4 = "Incorrect-Code.html"
        $spec_file5 = "Carte_Cpay.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
