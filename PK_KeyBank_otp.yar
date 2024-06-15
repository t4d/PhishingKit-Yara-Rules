rule PK_KeyBank_otp : KeyBank
{
    meta:
        description = "Phishing Kit impersonating KeyBank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7198548331063640064"
        date = "2024-06-11"
        comment = "Phishing Kit - KeyBank - asking for OTP"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "bootstrap"
        $spec_dir2 = "assets"
        $spec_dir3 = "css"
        // specific files found in PhishingKit
        $spec_file = "ssn.html"
        $spec_file2 = "license.html"
        $spec_file3 = "telegram.php"
        $spec_file4 = "otp.html"
        $spec_file5 = "key_white_logo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
       $local_file and 
       all of ($spec_dir*) and 
       all of ($spec_file*)
}
