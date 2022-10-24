rule PK_WellsFargo_mrweebee : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-18"
        comment = "Phishing Kit - Wells Fargo - '[MRWEEBEE]'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "settings"
        $spec_dir2 = "ses"
        // specific file found in PhishingKit
        $spec_file = "emma.php"
        $spec_file2 = "personal.php"
        $spec_file3 = "settings.php"
        $spec_file4 = "role.php"
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
