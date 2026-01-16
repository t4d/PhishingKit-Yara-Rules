rule PK_CanadaPost_blackforce : CanadaPost
{
    meta:
        description = "Phishing Kit impersonating Canada Post"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-01-09"
        comment = "Phishing Kit - Canada Post - BlackForce"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Canada Post - Track a package by tracking number_files"
        $spec_dir2 = "x_files"
        // specific files found in PhishingKit
        $spec_file = "layout_canadapost.php"
        $spec_file2 = "fees_payment.php"
        $spec_file3 = "telMain.js"
        $spec_file4 = "blackforce.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
