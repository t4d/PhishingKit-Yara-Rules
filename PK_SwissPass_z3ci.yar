rule PK_SwissPass_z3ci : SwissPass
{
    meta:
        description = "Phishing Kit impersonating SwissPass.ch"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-08-31"
        comment = "Phishing Kit - SwissPass - '- Z3CI -'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "CHFINALE"
        $spec_dir2 = "f3636"
        // specific file found in PhishingKit
        $spec_file = "configuration.php"
        $spec_file2 = "load2.html"
        $spec_file3 = "swisspass.min-20200819.js.download"
        $spec_file4 = "mcidcheck-visasecure.png"
        $spec_file5 = "send4.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
