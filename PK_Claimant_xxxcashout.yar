rule PK_Claimant_xxxcashout : Claimant
{
    meta:
        description = "Phishing Kit impersonating a Claimant Self Service portal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-17"
        comment = "Phishing Kit - Claimant - '! icq @716199390!' aka XXX Cashout"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "app"
        $spec_dir2 = "prevents"
        $spec_dir3 = "Claimant Two Factor Authentication_files"
        // specific files found in PhishingKit
        $spec_file1 = "top_banner_02-2.png"
        $spec_file2 = "Email.php"
        $spec_file3 = "algo.php"
        $spec_file4 = "post2.php"
        $spec_file5 = "DWD_seal_sm2.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
