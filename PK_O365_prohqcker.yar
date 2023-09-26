rule PK_O365_prohqcker : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-26"
        comment = "Phishing Kit - Office 365 - 'From: Prohqcker'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "core"
        $spec_dir1 = "security"
        $spec_file1 = "prohqcker4.php"
        $spec_file2 = "c.html"
        $spec_file3 = "me.php"
        $spec_file4 = "otp.html"
        $spec_file5 = "index3.html"
        $spec_file6 = "arrow_left.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
