rule PK_GCash_telegram : GCash
{
    meta:
        description = "Phishing Kit impersonating GCash"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-31"
        comment = "Phishing Kit - GCash - using Telegram for exfiltration"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "gcash_js"
        $spec_dir2 = "Gcash_files"
        // specific file found in PhishingKit
        $spec_file = "tele_bot.php"
        $spec_file2 = "config.php"
        $spec_file3 = "mpin-redir-login.php"
        $spec_file4 = "otp-login.php"
        $spec_file5 = "mpinerror2.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
