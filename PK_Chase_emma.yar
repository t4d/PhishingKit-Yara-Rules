rule PK_Chase_emma : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.stalkphish.com"
        date = "2024-11-17"
        comment = "Phishing Kit - Chase Bank - using emma.php named file"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "settings"
        $spec_dir2 = "Logs"
        $spec_dir3 = "night"
        // specific files found in PhishingKit
        $spec_file = "settings.php"
        $spec_file2 = "emma.php"
        $spec_file3 = "PERSONAL.js"
        $spec_file4 = "Chase_Octagon.svg"
        $spec_file5 = "background.desktop.12.jpeg"

    condition:
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
