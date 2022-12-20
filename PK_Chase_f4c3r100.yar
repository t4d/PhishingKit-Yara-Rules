rule PK_Chase_f4c3r100 : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-20"
        comment = "Phishing Kit - Chase Bank - '@F4C3R100'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Botslogs"
        $spec_dir2 = "vp"
        // specific files found in PhishingKit
        $spec_file = "failed_.php"
        $spec_file2 = ".htaccess.bak"
        $spec_file3 = "results.txt"
        $spec_file4 = "perso.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
