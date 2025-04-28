rule PK_SFR_makaveli : SFR
{
    meta:
        description = "Phishing Kit impersonating SFR Mail"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-25"
        comment = "Phishing Kit - SFR Mail - use a 'makaveli' directory name"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "makaveli"
        $spec_dir2 = "files"
        // specific file found in PhishingKit
        $spec_file = "post.php"
        $spec_file2 = "trust.php"
        $spec_file3 = "anti0.php"
        $spec_file4 = "anti9.php"
        $spec_file5 = "sprite-mire-2016.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
