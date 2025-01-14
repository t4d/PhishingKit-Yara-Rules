rule PK_PayPal_0x : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-14"
        comment = "Phishing Kit - Paypal - MR-0X'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "cssfls"
        $spec_dir2 = "krt2-Dateien"
        // specific file found in PhishingKit
        $spec_file = "opism2.php"
        $spec_file2 = "opi.php"
        $spec_file3 = "processing2.html"
	    $spec_file4 = "monogram-small@2x.png"
        $spec_file5 = "PayPalSansSmall-Regular.woff"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
	    all of ($spec_dir*)
}
