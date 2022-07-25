rule PK_WellsFargo_zhex : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-22"
        comment = "Phishing Kit - Wells Fargo - Z-Hex kit by Z-OReoo"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "admin"
        $spec_dir2 = "libraries"
        $spec_dir3 = "prevents"
        // specific file found in PhishingKit
        $spec_file = "dashboard.php"
        $spec_file2 = "Handler.php"
        $spec_file3 = "double_email.php"
        $spec_file4 = "quality.php"
        $spec_file5 = "COB-BOB-IRT-enroll_balloons.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}

