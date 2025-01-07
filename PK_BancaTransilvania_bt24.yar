rule PK_BancaTransilvania_bt24 : BancaTransilvania
{
    meta:
        description = "Phishing Kit impersonating Banca Transilvania"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-07"
        comment = "Phishing Kit - Banca Transilvania - 'bt24'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "def"
        $spec_dir2 = "inc"
        $spec_dir3 = "secrets"
        // specific file found in PhishingKit
        $spec_file = "mphone.php"
        $spec_file2 = "banned_ips_ipv6.txt"
        $spec_file3 = "userInfo.php"
        $spec_file4 = "cc_otp.txt"
        $spec_file5 = "bt-24-login.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
