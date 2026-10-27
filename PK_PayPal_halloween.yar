rule PK_PayPal_halloween : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7520047506286612480/"
        date = "2026-10-25"
        comment = "Phishing Kit - Paypal - with Halloween theme admin panel"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Chapta"
        $spec_dir2 = "panel"
        $spec_dir3 = "web"
        $spec_dir4 = "antibots"
        // specific file found in PhishingKit
        $spec_file = "admin.json"
        $spec_file2 = "VIC-127.0.0.1.json"
        $spec_file3 = "tg.php"
	    $spec_file4 = "captured.txt"
        $spec_file5 = "paypal_spinner_success_check@3x.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
	    all of ($spec_dir*)
}
