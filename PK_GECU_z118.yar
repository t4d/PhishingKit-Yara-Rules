rule PK_GECU_z118 : GECU
{
    meta:
        description = "Phishing Kit impersonating GECU Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-24"
        comment = "Phishing Kit - GECU - Using $Z118_* variables"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "grabber"
        $spec_dir2 = "assets"
        $spec_dir3 = "functions"
        // specific file found in PhishingKit
        $spec_file = "fullz.php"
        $spec_file2 = "session_relogin.php"
        $spec_file3 = "FLUID-Icons.ce11234f.ttf"
        $spec_file4 = "geculogo_200px75px-AxzG4.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
