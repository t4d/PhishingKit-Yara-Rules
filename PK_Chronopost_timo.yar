rule PK_Chronopost_timo : Chronopost
{
    meta:
        description = "Phishing Kit impersonating Chronopost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-09-23"
        comment = "Phishing Kit - Chronopost - 'From: Timo <noreply@ionos.org>'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "app"
        $spec_dir2 = "poste_files"
        // specific files found in PhishingKit
        $spec_file = "autentification.css"
        $spec_file1 = "submitInfo3.php"
        $spec_file2 = "paiement.php"
        $spec_file3 = "logo-chronopost-international.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
