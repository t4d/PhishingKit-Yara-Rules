rule PK_MTB_mj : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-24"
        comment = "Phishing Kit - M&T Bank - '-  XXX-MJ  -'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "fonts"
        // specific files found in PhishingKit
        $spec_file = "mandtpg-iconfont.woff"
        $spec_file2 = "mandtbaltoweb-book.woff"
        $spec_file3 = "index.html"
        $spec_file4 = "___.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*) 
}
