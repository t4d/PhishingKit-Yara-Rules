rule PK_O365_racers : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-21"
        comment = "Phishing Kit - Office 365 - 'site_admin_username=Racers"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "login-microsoftonline_files"
        $spec_file1 = "cdb.php"
        $spec_file2 = "settings.php"
        $spec_file3 = "datastore32.db"
        $spec_file4 = "microsoft_logo_564db913a7fa0ca42727161c6d031bef.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
