rule PK_DropBox_gpapa : Dropbox
{
    meta:
        description = "Phishing Kit impersonating DropBox"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-03"
        comment = "Phishing Kit - DropBox - '| By G Papa |'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "img"
        // specific files found in PhishingKit
        $spec_file = "remail.php"
        $spec_file2 = "ver.pdf.php"
        $spec_file3ac = "go.php"
        $spec_file4 = "home-hero@2x-vfl9GE_2I.jpg"

    condition:
        // look for the ZIP header and all
        uint32(0) == 0x04034b50 and
        $local_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
