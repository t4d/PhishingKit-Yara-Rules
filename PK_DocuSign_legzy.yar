rule PK_DocuSign_legzy : DocuSign
{
    meta:
        description = "Phishing Kit impersonating DocuSign"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-02-09"
        comment = "Phishing Kit - DocuSign - 'Created by legzy'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "docusign"
        $spec_file1 = "CONTROLS.php"
        $spec_file2 = "netcraft_check.php"
        $spec_file3 = "ip_range_check.php"
        $spec_file4 = "blacklist_lookup.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}