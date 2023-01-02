rule PK_Chronopost_asloo : Chronopost
{
    meta:
        description = "Phishing Kit impersonating Chronopost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-01"
        comment = "Phishing Kit - Chronopost - '- ASLOO  -'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "vendor"
        // specific files found in PhishingKit
        $spec_file = "hawta.php"
        $spec_file1 = "Monsuivi.apk"
        $spec_file2 = "track.html"
        $spec_file3 = "car.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
