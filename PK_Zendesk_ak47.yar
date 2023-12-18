rule PK_Zendesk_ak47: Zendesk
{
    meta:
        description = "Phishing Kit impersonating Zendesk"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-13"
        comment = "Phishing Kit - Zendesk - 'From: Ak47.BUlLETS'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "assets"
        $spec_dir2 = "bootstrap"
        $spec_file = "shond.php"
        $spec_file2 = "shondxt.php"
        $spec_file3 = "HLQckvmEStzm0YAHgTac1694910463.png"
        $spec_file4 = "Login-Box-En-login-box-en.css"
        $spec_file5 = "zendesksupport.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
