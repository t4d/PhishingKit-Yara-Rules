rule PK_WellsFargo_RD265 : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-16"
        comment = "Phishing Kit - Wells Fargo - using RD265 in archive name - reference to 'venza'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "card.html"
        $spec_file2 = "next.php"
        $spec_file3 = "email.php"
        $spec_file4 = "detail.html"
        $spec_file5 = "WF_stagecoach_rgb_ylw_F1.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
