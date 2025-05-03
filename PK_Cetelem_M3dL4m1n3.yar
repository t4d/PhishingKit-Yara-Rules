rule PK_Cetelem_M3dL4m1n3 : Cetelem
{
    meta:
        description = "Phishing Kit impersonating Cetelem"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-03"
        comment = "Phishing Kit - Cetelem - 'c0ded By M3dL4m!n3'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "verification"
        $spec_dir2 = "index"
        $spec_dir3 = "uploads"
        // specific files found in PhishingKit
        $spec_file = "password.php"
        $spec_file2 = "cc.php"
        $spec_file3 = "email.php"
        $spec_file4 = "logo-large.png"
        $spec_file5 = "cetelem-full-page.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
