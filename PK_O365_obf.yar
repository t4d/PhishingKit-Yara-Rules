rule PK_O365_obf : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-20"
        comment = "Phishing Kit - Office 365 - obfuscated files"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "lib"
        $spec_file1 = "funcations.php"
        $spec_file2 = "ghome.php"
        $spec_file3 = "opps.html"
        $spec_file4 = "vm.mp3"
        $spec_file5 = "web.config"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}