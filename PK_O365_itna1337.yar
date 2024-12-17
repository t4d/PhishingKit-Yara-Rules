rule PK_O365_itna1337 : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-12-11"
        comment = "Phishing Kit - O365 - 'This Page Made By : itna1337'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Sign in to your Microsoft account_files"
        $spec_dir2 = "phoennumberpage_files"
        // specific files found in PhishingKit
        $spec_file = "cred.php"
        $spec_file2 = "convergedlogin_ppassword_9235db024183cbbda7d8.js"
        $spec_file3 = "contgen.php"
        $spec_file4 = "microsoft_logo_ee5c8d9fb6248c938fd0dc19370e90bd.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
