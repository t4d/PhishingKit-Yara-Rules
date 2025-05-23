rule PK_GoogleVoice_rewz : GoogleVoice
{
    meta:
        description = "Phishing Kit impersonating Google Voice service"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-12"
        comment = "Phishing Kit - Google Voice - 'From: REWZ@$server'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        // specific file found in PhishingKit
        $spec_file = "index_0f_invalid.php"
        $spec_file2 = "index_other.php"
        $spec_file3 = "rewz_cod.php"
        $spec_file4 = "rewz_other_invalid.php"
        $spec_file5 = "klik.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}
