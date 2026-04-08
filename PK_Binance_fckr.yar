rule PK_Binance_fckr : Binance
{
    meta:
        description = "Phishing Kit impersonating Binance"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-04-08"
        comment = "Phishing Kit - Binance - using 'fckr' directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "fckr"
        $spec_dir2 = "metamask"
        $spec_dir3 = "rainbowwallet"       
        $spec_file1 = "configs.json"
        $spec_file2 = "auth.php"
        $spec_file3 = "import-wallet.html"
        $spec_file4 = "nami.png"
        $spec_file5 = "import-with-recovery-phrase.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
