rule PK_DropBox_2023 : Dropbox
{
    meta:
        description = "Phishing Kit impersonating DropBox"
        licence = ""
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-20"
        comment = "Phishing Kit - DropBox - '2023dropbox'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        // specific files found in PhishingKit
        $spec_file = "AOL.html"
        $spec_file2 = "001100110011yahoo.html"
        $spec_file3 = "success.php"
        $spec_file4 = "Outlookheader.png"

    condition:
        // look for the ZIP header and all
        uint32(0) == 0x04034b50 and
        $local_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
