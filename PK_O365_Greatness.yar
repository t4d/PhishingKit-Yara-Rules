rule PK_O365_Greatness: Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365 - Greatness PaaS campaigns"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = "https://blog.talosintelligence.com/new-phishing-as-a-service-tool-greatness-already-seen-in-the-wild/"
        date = "2023-06-28"
        comment = "Phishing Kit - Office 365 - 'Greatness Boss'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "admin/js/"
        $spec_file1 = "mj.php"
        $spec_file2 = "httpd.grt"
        $spec_file3 = "j2.php"
        $spec_file4 = "config.ini"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
