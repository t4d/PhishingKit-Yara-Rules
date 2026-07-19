rule PK_DHL_antinspect : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-05"
        comment = "Phishing Kit - DHL - contains anti-inspection tricks"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "anti1"
        $spec_dir2 = "api"
        $spec_dir3 = "store"
        $spec_file1 = "tokenerror.php"
        $spec_file2 = "send_billing_plan.php"
        $spec_file4 = "anti-inspect.js"
        $spec_file5 = "page_tracks.json"
        $spec_file6 = "dhl-icon.svg"
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
