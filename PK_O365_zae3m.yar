rule PK_O365_zae3m : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-01"
        comment = "Phishing Kit - O365 - 'By Zae3m' based on RD85 with Telegram exfil."

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_dir2 = "prevents"
        // specific files found in PhishingKit
        $spec_file = "email.php"
        $spec_file2 = "next.php"
        $spec_file3 = "success.PNG"
        $spec_file4 = "microsoft_logo.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
