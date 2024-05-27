rule PK_KeyBank_chibouna : KeyBank
{
    meta:
        description = "Phishing Kit impersonating KeyBank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7198548331063640064"
        date = "2024-05-27"
        comment = "Phishing Kit - KeyBank - 'KeyBank ScamPage By CH1BOUNA'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Inc"
        $spec_dir2 = "process"
        $spec_dir3 = "css"
        // specific files found in PhishingKit
        $spec_file = "thank-you.php"
        $spec_file2 = "billing.php"
        $spec_file3 = "email2.php"
        $spec_file4 = "kds.svg"
        $spec_file5 = "styles.575c0fc509b20a788593.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
       $local_file and 
       all of ($spec_dir*) and 
       all of ($spec_file*)
}
