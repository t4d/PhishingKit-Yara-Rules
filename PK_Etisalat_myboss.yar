rule PK_Etisalat_myboss : Etisalat
{
    meta:
        description = "Phishing Kit impersonating Etisalat"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-25"
        comment = "Phishing Kit - Etisalat - 'Cc: myboss@example.com'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "PaymentEx"
        $spec_dir2 = "3ds"
        $spec_dir3 = "fonts"
        // specific file found in PhishingKit
        $spec_file = "handler.php"
        $spec_file2 = "payment.php"
        $spec_file3 = "start_transaction.php"
        $spec_file4 = "cookie.js"
        $spec_file5 = "eWFiYWx0b2dvcm90.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
