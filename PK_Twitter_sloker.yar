rule PK_Twitter_sloker : Twitter
{
    meta:
        description = "Phishing Kit impersonating Twitter"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-27"
        comment = "Phishing Kit - Twitter - 'BY CODER SLOKER'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "sloker"
        // specific file found in PhishingKit
        $spec_file = "confirmed.php"
        $spec_file2 = "username.php"
        $spec_file3 = "tg.php"
        $spec_file4 = "twigif1.gif"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}
