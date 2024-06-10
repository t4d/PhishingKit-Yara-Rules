rule PK_RAM_otp : RAM
{
    meta:
        description = "Phishing Kit impersonating RAM.co.za"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-03-27"
        comment = "Phishing Kit - RAM - retrieved also One-Time-Password code"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "me.php"
        $spec_file2 = "cc.html"
        $spec_file3 = "config.php"
        $spec_file4 = "wait.html"
        $spec_file5 = "coderror.html"
        $spec_file6 = "succes.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
