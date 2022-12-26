rule PK_Coinbase_stillalive : Coinbase
{
    meta:
        description = "Phishing Kit impersonating Coinbase"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-22"
        comment = "Phishing Kit - Coinbase - Actor: '@Facebook - https://www.facebook.com/ownerstillalive/'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "2fa"
        $spec_dir2 = "account_recovery"
        // specific files found in PhishingKit
        $spec_file1 = "update_drop.php"
        $spec_file2 = "example-selfie.png"
        $spec_file3 = "proxyorvpnblock.php"
        $spec_file4 = "failedotpauth_drop.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
