rule PK_Interac_bore3da : interac
{
    meta:
        description = "Phishing Kit impersonating Interac, several payment systems"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-08"
        comment = "Phishing Kit - Interac - 'Main Author: Bore3da'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "core"
        $spec_dir2 = "tower"
        $spec_file1 = "configg.php"
        $spec_file2 = "validatevisitorz.php"
        $spec_file3 = "interac-jqm.css"
        $spec_file4 = "etransfer_logo.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
