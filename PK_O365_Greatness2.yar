rule PK_O365_Greatness2: Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365 - Greatness PaaS campaigns"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = "https://stalkphish.com/2023/07/04/threat-intelligence-about-the-paas-named-greatness/"
        comment = "Phishing Kit - Office 365 - Greatness tool since version "

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "admin/js/"
        $spec_file1 = "mp.php"
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
