rule PK_Twitter_Khontkar : Twitter
{
    meta:
        description = "Phishing Kit impersonating Twitter"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-17"
        comment = "Phishing Kit - Twitter - reference to Khontkar lyrics (a Turkish rapper)"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "img"
        // specific file found in PhishingKit
        $spec_file = "banane.php"
        $spec_file2 = "banane1.php"
        $spec_file3 = "yavru.php"
        $spec_file4 = "twitter.png"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}
