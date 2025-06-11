rule PK_Stripe_db : Stripe
{
    meta:
        description = "Phishing Kit impersonating Stripe"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-07"
        comment = "Phishing Kit - Stripe - Using local DB+Telegram"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "api"
        $spec_dir2 = "src"
        $spec_file1 = "cardHandler.php"
        $spec_file2 = "custom.php"
        $spec_file3 = "bot.py"
        $spec_file4 = "createCheckout.php"
        $spec_file5 = "stripe.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
