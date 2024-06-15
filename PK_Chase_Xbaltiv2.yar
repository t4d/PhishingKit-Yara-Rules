rule PK_Chase_Xbaltiv2 : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-27"
        comment = "Phishing Kit - Chase Bank - XBalti"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "XBALTI"
        $spec_dir2 = "admin"
        $spec_dir3 = "fonts"
        // specific files found in PhishingKit
        $spec_file = "chasefavicon.ico"
        $spec_file2 = "Email.php"
        $spec_file3 = "antifuck.php"
        $spec_file4 = "imageprofile.php"
        $spec_file5 = "mds-chase-icons.eot"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
