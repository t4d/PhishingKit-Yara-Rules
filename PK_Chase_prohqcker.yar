rule PK_Chase_prohqcker : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-07"
        comment = "Phishing Kit - Chase Bank - 'Prohqcker_Bot*CHASE BANK'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "file"
        $spec_dir2 = "images"
        $spec_dir3 = "fonts"
        // specific files found in PhishingKit
        $spec_file = "otp2.html"
        $spec_file2 = "c.html"
        $spec_file3 = "vthreeallFullCss.css"
        $spec_file4 = "db_connect4.php"
        $spec_file5 = "Logo.png"
        $spec_file6 = "224.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
