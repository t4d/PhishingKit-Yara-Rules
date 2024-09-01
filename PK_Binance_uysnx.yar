rule PK_Binance_uysnx : Binance
{
    meta:
        description = "Phishing Kit impersonating Binance"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-28"
        comment = "Phishing Kit - Binance - using 'UysnX' directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "UysnX"
        $spec_dir2 = "js_main"
        $spec_file1 = "khawazmiat_binance.php"
        $spec_file2 = "frifayr.php"
        $spec_file3 = "7adari_ababab.js"
        $spec_file4 = "script_binance.php"
        $spec_file5 = "uysnx.gif"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
