rule PK_Amex_ghostrider : Amex
{
    meta:
        description = "Phishing Kit impersonating American Express"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-26"
        comment = "Phishing Kit - Amex - '-|Ghost Rider|-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "bots"
        $spec_dir2 = "sending"

        $spec_file1 = "cok.php"
        $spec_file2 = "Yourmail.php"
        $spec_file3 = "verify-card.php"
        $spec_file4 = "personal.php"
        $spec_file5 = "amex-desktop-logo.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
