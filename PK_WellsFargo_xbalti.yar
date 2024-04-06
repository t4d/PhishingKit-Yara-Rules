rule PK_WellsFargo_xbalti : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-03"
        comment = "Phishing Kit - Wells Fargo - 'WELLS BY X V1'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir2 = "my"
        $spec_dir3 = "js"
        // specific file found in PhishingKit
        $spec_file = "captcha.php"
        $spec_file2 = "Update.php"
        $spec_file3 = "hooks.php"
        $spec_file4 = "mstyle.css"
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
