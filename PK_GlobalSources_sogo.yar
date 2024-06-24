rule PK_GlobalSources_sogo : GlobalSources
{
    meta:
        description = "Phishing Kit impersonating GlobalSources"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-11-30"
        comment = "Phishing Kit - GlobalSources - 'SOGO'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "files"
        $spec_file1 = "screenstyle_en_US.css"
        $spec_file2 = "trap.php"
        $spec_file3 = "SSO2.CSS"
        $spec_file4 = "GSLOGO.PNG"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
