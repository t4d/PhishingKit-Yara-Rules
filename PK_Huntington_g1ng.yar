rule PK_Huntington_g1ng : Huntington
{
    meta:
        description = "Phishing Kit impersonating Huntington bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-25"
        comment = "Phishing Kit - Huntington Bank - '[+] G 1 N G  [+]'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "assets_files"
        $spec_dir2 = "otp_files"
        // specific file found in PhishingKit
        $spec_file = "load2.php"
        $spec_file2 = "sms-error.php"
        $spec_file3 = "postToServer.min.html"
        $spec_file4 = "logo-honeycomb.svg"
    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
