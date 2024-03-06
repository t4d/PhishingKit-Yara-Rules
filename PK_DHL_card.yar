rule PK_DHL_card : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-11-22"
        comment = "Phishing Kit - DHL - 'DHL | Card'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "inc"
        $spec_dir2 = "login"
        $spec_dir3 = "countdowntimer"
        $spec_file1 = "composer.json"
        $spec_file2 = "resultab4.txt"
        $spec_file4 = "loading2.php"
        $spec_file5 = "details.php"
        $spec_file6 = "airplan.png"
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
