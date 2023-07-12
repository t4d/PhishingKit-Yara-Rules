rule PK_Netflix_fsociety : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-11"
        comment = "Phishing Kit - Netflix - 'C0d3d by fS0C13TY_Team'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Bots-fSOCIETY"
        $spec_dir2 = "style"
        // specific file found in PhishingKit
        $spec_file = "Add_Your_TelegramAPi.php"
        $spec_file2 = "sand_email.php"
        $spec_file3 = "Myaccount_Sms.php"
        $spec_file4 = "nficon2016.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
