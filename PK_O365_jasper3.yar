rule PK_O365_jasper3 : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1605307296954941440"
        date = "2022-12-20"
        comment = "Phishing Kit - O365 - 'Created By JaSpEr'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file = "Login.php"
        $spec_file2 = "index.htm"
        $spec_file3 = "passfailed.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
