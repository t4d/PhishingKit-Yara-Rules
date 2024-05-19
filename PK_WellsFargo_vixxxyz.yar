rule PK_WellsFargo_vixxxyz : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-07"
        comment = "Phishing Kit - Wells Fargo - 'This is WellsFargo  Scampage By @VixxxyZ'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "admin"
        $spec_dir2 = "Export"
        $spec_dir3 = "VixxxyZ"
        // specific file found in PhishingKit
        $spec_file = "duallogin.php"
        $spec_file2 = "kill.txt"
        $spec_file3 = "cleave.js"
        $spec_file4 = "vixxxyz5.php"
        $spec_file5 = "wellsfargoserif-sbd.woff2"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
