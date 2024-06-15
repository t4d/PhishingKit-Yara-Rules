rule PK_SwissPass_blackforce : SwissPass
{
    meta:
        description = "Phishing Kit impersonating SwissPass SBBCFF (sbb.ch)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-06-11"
        comment = "Phishing Kit - SwissPass - 'blackforce - Coded By Root_Dr'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Config"
        $spec_dir2 = "Panel"
        $spec_dir3 = "botActBan"
        $spec_file1 = "suissLog.php"
        $spec_file2 = "swissPass.php"
        $spec_file3 = "loader.php"
        $spec_file4 = "hacker-25929.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
