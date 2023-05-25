rule PK_BDO_advancedspamming : BDO
{
    meta:
        description = "Phishing Kit impersonating BDO Unibank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-20"
        comment = "Phishing Kit - BDO - '@ADVANCEDSPAMMING'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "php_components"
        $spec_dir2 = "js_scripts"
        $spec_dir3 = "APIs"
        $spec_file1 = "mobile_number.js"
        $spec_file2 = "mobile_number.php"
        $spec_file3 = "one_time_password.php"
        $spec_file4 = "antibot_pw.api.php"
        $spec_file5 = "sendMessage.telegram.php"
        $spec_file6 = "bdo-logo.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
