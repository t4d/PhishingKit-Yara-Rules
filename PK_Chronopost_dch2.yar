rule PK_Chronopost_dch2 : Chronopost
{
    meta:
        description = "Phishing Kit impersonating Chronopost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-13"
        comment = "Phishing Kit - Chronopost - 'DCH Coder'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "sourceApp"
        // specific files found in PhishingKit
        $spec_file = "chronopost_tours_03712200_113425863.jpg"
        $spec_file1 = "remettions-page.php"
        $spec_file2 = "engagement-page.php"
        $spec_file3 = "funciones.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}