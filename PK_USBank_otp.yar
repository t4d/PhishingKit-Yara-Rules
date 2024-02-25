rule PK_USBank_otp : USBank
{
    meta:
        description = "Phishing Kit impersonating U.S. Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-12"
        comment = "Phishing Kit - USBank"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "assets"
        $spec_dir2 = "bootstrap"
        // specific file found in PhishingKit
        $spec_file = "email.php"
        $spec_file2 = "phone.html"
        $spec_file3 = "empass.html"
        $spec_file4 = "telegram.php"
        $spec_file5 = "lg.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
