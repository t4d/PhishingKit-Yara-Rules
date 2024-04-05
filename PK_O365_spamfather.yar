rule PK_O365_spamfather: Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-02"
        comment = "Phishing Kit - Office 365 - spamfather"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "gms.html"
        $spec_file3 = "mega.js"
        $spec_file4 = "index.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}
