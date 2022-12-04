rule PK_Coinbase_c0d3d : Coinbase
{
    meta:
        description = "Phishing Kit impersonating Coinbase"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-30"
        comment = "Phishing Kit - Coinbase - '-+ C0d3d by anonymous +-'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "coinbase_files"
        // specific files found in PhishingKit
        $spec_file1 = "coinbase.html"
        $spec_file2 = "tk1.php"
        $spec_file3 = "important1.html"
        $spec_file4 = "reset.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
