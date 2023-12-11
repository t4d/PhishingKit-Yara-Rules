rule PK_UPS_acs : UPS
{
    meta:
        description = "Phishing Kit impersonating UPS"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-15"
        comment = "Phishing Kit - UPS - '<title>ACS</title>'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "files"
        // specific file found in PhishingKit
        $spec_file = "ajax-loader-transparent.gif"
        $spec_file2 = "libs.bundle.d4af436688895680.css"
        $spec_file3 = "vbv.html"
        $spec_file4 = "ups.css"
        $spec_file5 = "UPS_logo.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
