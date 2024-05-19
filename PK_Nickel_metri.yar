rule PK_Nickel_metri : Nickel
{
    meta:
        description = "Phishing Kit impersonating Nickel"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7197112043672416256"
        date = "2024-05-16"
        comment = "Phishing Kit - Nickel - 'Coded by METRI'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "nkl_files"
        $spec_dir2 = "rezult"
        $spec_dir3 = "visites"
        // specific file found in PhishingKit
        $spec_file = "nkl-infos.php"
        $spec_file2 = "M3tri-control.php"
        $spec_file3 = "Error.php"
        $spec_file4 = "HunterObfuscator.php"
        $spec_file5 = "nkl-otp.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
