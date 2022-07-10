rule PK_Coinbase_spm55 : Coinbase
{
    meta:
        description = "Phishing Kit impersonating Coinbase"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-29"
        comment = "Phishing Kit - Coinbase - '=[ SPM55 - PRIVATE COINBASE ]='"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "error_page"
        $spec_dir2 = "phone_validation"
        // specific files found in PhishingKit
        $spec_file1 = "logs2.php"
        $spec_file2 = "l.php"
        $spec_file3 = "email.php"
        $spec_file4 = "reset_password.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
