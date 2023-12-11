rule PK_PayPal_it : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-12-01"
        comment = "Phishing Kit - Paypal - targets italian speakers"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "static"
        // specific file found in PhishingKit
        $spec_file = "conferma2.php"
        $spec_file2 = "main.js"
        $spec_file3 = "mini-spinner.php"
	    $spec_file4 = "convalida.php"
        $spec_file5 = "redirect.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
	    all of ($spec_dir*)
}
