rule PK_BSI_saldo2 : BSI
{
    meta:
        description = "Phishing Kit impersonating Bank Syariah Indonesia (BSI)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-30"
        comment = "Phishing Kit - BSI - 'saldo'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "req"
        $spec_dir2 = "auth"
        // specific file found in PhishingKit
        $spec_file = "otp.html"
        $spec_file2 = "saldo.php"
        $spec_file3 = "mailman.php"
        $spec_file4 = "telegram.php"
        $spec_file5 = "otp.png"
        $spec_file6 = "bank-syariah-indonesia.webflow.681e682db.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
