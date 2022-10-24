rule PK_Chase_a9x : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-22"
        comment = "Phishing Kit - Chase Bank - 'From: A9X Chase <a9x@spme.com>'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "auth"
        $spec_dir2 = "css"
        // specific files found in PhishingKit
        $spec_file = "chase.png"
        $spec_file2 = "verification-email.php"
        $spec_file3 = "verification-billing.php"
        $spec_file4 = "po3.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
