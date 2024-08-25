rule PK_Chase_drfxnd : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-25"
        comment = "Phishing Kit - Chase Bank - '@DrFXND'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "res"
        $spec_dir2 = "send"
        $spec_dir3 = "lib"
        // specific files found in PhishingKit
        $spec_file = "personal.php"
        $spec_file2 = "sms.php"
        $spec_file3 = "log.php"
        $spec_file4 = "personal.php"
        $spec_file5 = "wait.php"
        $spec_file6 = "chase.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
