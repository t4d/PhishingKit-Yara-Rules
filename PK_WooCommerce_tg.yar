rule PK_WooCommerce_tg : WooCommerce
{
    meta:
        description = "Phishing Kit impersonating WooCommerce.com"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-04-03"
        comment = "Phishing Kit - WooCommerce - using telegram for exfiltration"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "telegram.php"
        $spec_file1 = "record.txt"
        $spec_file2 = "next.php"
        $spec_file4 = "woo.png"
        $spec_file5 = "8316.0ce0ab45487acf8d1ff1.min.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
