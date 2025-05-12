rule PK_Kraken_kenshin : Kraken
{
    meta:
        description = "Phishing Kit impersonating Kraken"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-21"
        comment = "Phishing Kit - Kraken - use a 'kenshinSamouraIP()' function"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "partial"
        $spec_dir2 = "remote"
        // specific files found in PhishingKit
        $spec_file = "CONFIG.php"
        $spec_file2 = "zero.php"
        $spec_file3 = "ReferralSpamDetect.php"
        $spec_file4 = "controller.php"
        $spec_file5 = "mobil-fr.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
