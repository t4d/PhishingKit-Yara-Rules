rule PK_Coinbase_mato : Coinbase
{
    meta:
        description = "Phishing Kit impersonating Coinbase"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-10-14"
        comment = "Phishing Kit - Coinbase - 'Mato Admin Panel'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "shade"
        $spec_dir2 = "page"
        // specific files found in PhishingKit
        $spec_file = "selfie.php"
        $spec_file1 = "google_otp.php"
        $spec_file2 = "victim.class.php"
        $spec_file3 = "KFOlCnqEu92Fr1MmEU9fBBc4AMP6lQ.woff2"
        $spec_file4 = "785.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
           $local_file and 
           all of ($spec_dir*) and 
           all of ($spec_file*)
}
