rule PK_MTBank_z118 : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-27"
        comment = "Phishing Kit - M&T Bank - '$Z118_EMAIL, $Z118_SUBJECT, $Z118_MESSAGE, $Z118_HEADERS'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "font"
        $spec_dir1 = "success"
        // specific files found in PhishingKit
        $spec_file = "caps.php"
        $spec_file2 = "Welcome to Online Banking _ M&T Bank.html"
        $spec_file3 = "lock.php"
        $spec_file4 = "mtb-equalhousinglender.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*) 
}
