rule PK_BPER_alpha : BPER
{
    meta:
        description = "Phishing Kit impersonating BPER Banca"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-18"
        comment = "Phishing Kit - BPER - 'From: car <no@alpha.com>'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "check4.php"
        $spec_file2 = "loading1.html"
        $spec_file3 = "otp2.html"
        $spec_file4 = "xx.png"
        $spec_file5 = "acce2.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
