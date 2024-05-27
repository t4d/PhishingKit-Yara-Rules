rule PK_BankOfAmerica_akhatar : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7198548331063640064"
        date = "2024-05-27"
        comment = "Phishing Kit - BankOfAmerica - 'Author: Hamid Akhatar'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "hamidhmds"
        $spec_dir2 = "inc"
        // specific file found in PhishingKit
        $spec_file = "cc.php"
        $spec_file2 = "failed_login.php"
        $spec_file3 = "emailk.php"
        $spec_file4 = "submit.php"
        $spec_file5 = "zz10.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
