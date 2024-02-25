rule PK_PayPal_pannello2 : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://x.com/AndreaDraghetti/status/1554437143203926016"
        date = "2024-02-10"
        comment = "Phishing Kit - Paypal - pannello2"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "autenticazione_files"
        $spec_dir2 = "otp_files"
        $spec_dir3 = "database"
        $spec_dir4 = "pannello2"
        // specific file found in PhishingKit
        $spec_file = "carta.php"
        $spec_file2 = "fine2.php"
        $spec_file3 = "link.php"
	    $spec_file4 = "cambiacartella.php"
        $spec_file5 = "glyph_alert_critical_big-2x.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
	    all of ($spec_dir*)
}
