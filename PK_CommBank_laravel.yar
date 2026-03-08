rule PK_CommBank_laravel : CommBank
{
    meta:
        description = "Phishing Kit impersonating Commonwealth Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-03-08"
        comment = "Phishing Kit - CommBank - Laravel app"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "commbank"
        $spec_dir2 = "commbank-assets"
        // specific files found in PhishingKit
        $spec_file = "businessbf8b.html"
        $spec_file1 = "commbank-yello249b.html"
        $spec_file2 = "EnsureTwoFactorAuth.php"
        $spec_file3 = "KycApplicationRequest.php"
        $spec_file4 = "Twofa.php"
        $spec_file5 = "commBank-logo.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
