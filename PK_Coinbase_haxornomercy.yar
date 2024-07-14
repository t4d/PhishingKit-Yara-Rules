rule PK_Coinbase_haxornomercy : Coinbase
{
    meta:
        description = "Phishing Kit impersonating Coinbase"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-13"
        comment = "Phishing Kit - Coinbase - 'From: haxornomercy"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "secured"
        $spec_dir2 = "app"
        $spec_dir3 = "season"
        // specific files found in PhishingKit
        $spec_file1 = "rsend.php"
        $spec_file2 = "sendselfie.php"
        $spec_file3 = "upload_id.html"
        $spec_file4 = "phonelog.php"
        $spec_file5 = "take-selfie.jpg"
        $spec_file6 = "favicon-196.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
