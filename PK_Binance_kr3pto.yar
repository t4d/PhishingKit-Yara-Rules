rule PK_Binance_kr3pto : Binance
{
    meta:
        description = "Phishing Kit impersonating Binance"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-01"
        comment = "Phishing Kit - Binance - '@Kr3pto on telegram'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "page_l0gz"
        $spec_dir2 = "binca_assetz"
        $spec_file1 = "binanceAnnouncement.php"
        $spec_file2 = "binanceSignUpComplete.php"
        $spec_file3 = "mob_lock.php"
        $spec_file4 = "BinancePlex-Bold.woff2"
        $spec_file5 = "binance-logo.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
