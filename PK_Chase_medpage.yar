rule PK_Chase_medpage : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-03-29"
        comment = "Phishing Kit - Chase Bank - '-created by medpage-'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "files"
        // specific files found in PhishingKit
        $spec_file = "personal.html"
        $spec_file2 = "complete.html"
        $spec_file3 = "logging.php"
        $spec_file4 = "personal.php"
        $spec_file5 = "chasefavicon.ico"
        $spec_file6 = "processing.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
