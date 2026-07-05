rule PK_PayPal_dati : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-17"
        comment = "Phishing Kit - Paypal - use 'dati' filenames"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "process"
        $spec_dir2 = "settings"
        $spec_dir3 = "spinner"
        $spec_file = "safe.html"
        $spec_file2 = "settings-visitor.php"
        $spec_file3 = "spinner-otp.php"
	    $spec_file4 = "user.html"
        $spec_file5 = "paypal-logo.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
	    all of ($spec_dir*)
}
