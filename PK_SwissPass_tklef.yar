rule PK_SwissPass_tklef : SwissPass
{
    meta:
        description = "Phishing Kit impersonating SwissPass.ch"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-07"
        comment = "Phishing Kit - SwissPass - using tklef.php filename"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Login _ SwissPass_files"
        $spec_dir2 = "swisspass.ch_files"
        $spec_dir3 = "inti"
        // specific file found in PhishingKit
        $spec_file = "done.php"
        $spec_file2 = "sign.php"
        $spec_file3 = "tklef.php"
        $spec_file4 = "swisspass.min-20200819.js.download"
        $spec_file5 = "logo-20200819.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
