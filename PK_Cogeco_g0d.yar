rule PK_Cogeco_g0d : Cogeco
{
    meta:
        description = "Phishing Kit impersonating Cogeco.ca"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-26"
        comment = "Phishing Kit - Cogeco - '-+ Created BY God +-'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "cog_files"
        // specific files found in PhishingKit
        $spec_file1 = "cogge.php"
        $spec_file2 = "cog.html"
        $spec_file3 = "account_version_check.html"
        $spec_file4 = "myaccount-duo-88.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
