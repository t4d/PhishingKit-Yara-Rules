rule PK_BSI_saldo : BSI
{
    meta:
        description = "Phishing Kit impersonating Bank Syariah Indonesia (BSI)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-06-11"
        comment = "Phishing Kit - BSI - 'saldo'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "send"
        // specific file found in PhishingKit
        $spec_file = "otp.html"
        $spec_file2 = "Saldo.php"
        $spec_file3 = "Nomor.php"
        $spec_file4 = "Debit.php"
        $spec_file5 = "data.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
