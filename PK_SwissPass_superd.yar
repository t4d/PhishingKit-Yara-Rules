rule PK_SwissPass_superd : SwissPass
{
    meta:
        description = "Phishing Kit impersonating SwissPass SBBCFF (sbb.ch)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-08-18"
        comment = "Phishing Kit - SwissPass - 'blackforce - Coded By Root_Dr'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "admin"
        $spec_dir2 = "posting"
        $spec_dir3 = "global"
        $spec_file1 = "track.php"
        $spec_file2 = "sending.php"
        $spec_file3 = "swisspass.min-20200819.js"
        $spec_file4 = "logo_text_de-20200819.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
    