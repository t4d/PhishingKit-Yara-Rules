rule PK_WellsFargo_mky : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-27"
        comment = "Phishing Kit - Wells Fargo - 'CREATED BY MkY'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Scv"
        $spec_dir2 = "CrawlerDetect"
        $spec_dir3 = "Os"
        // specific file found in PhishingKit
        $spec_file = "alert.php"
        $spec_file2 = "Botsettings.ini"
        $spec_file3 = "Aemail.php"
        $spec_file4 = "Setmodule.php"
        $spec_file5 = "SendModule.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
