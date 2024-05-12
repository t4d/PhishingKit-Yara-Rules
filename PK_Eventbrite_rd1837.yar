rule PK_Eventbrite_rd1837: Eventbrite
{
    meta:
        description = "Phishing Kit impersonating Eventbrite"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-09"
        comment = "Phishing Kit - Eventbrite - RD1837"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        $spec_dir2 = "css"
        // specific file found in PhishingKit
        $spec_file = "2228.47226e6f5101ad6dd1d7.css"
        $spec_file2 = "eds.css"
        $spec_file3 = "lateral-image-2-hd.jpg"
        $spec_file4 = "next.php"
        $spec_file5 = "email.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
