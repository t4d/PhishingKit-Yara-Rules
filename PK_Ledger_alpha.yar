rule PK_Ledger_alpha : Ledger
{
    meta:
        description = "Phishing Kit impersonating Ledger"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-02"
        comment = "Phishing Kit - Ledger - 'From: bper <no@alpha.com>'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Ledger Support_files"
        // specific file found in PhishingKit
        $spec_file = "check3.php"
        $spec_file2 = "LedgerSupport.html"
        $spec_file3 = "768d0df29086c98763c6c0907a5aed1f76ae9306.svg"
        $spec_file4 = "bip39.browser.min.js.download"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
