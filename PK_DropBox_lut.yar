rule PK_DropBox_lut : Dropbox
{
    meta:
        description = "Phishing Kit impersonating DropBox"
        licence = ""
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-26"
        comment = "Phishing Kit - DropBox - '$from = Lut@Tech.com'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Drop_files"
        $spec_dir2 = "a_data"
        // specific files found in PhishingKit
        $spec_file = "a.htm"
        $spec_file2 = "bat.js"
        $spec_file3 = "dismiss-cross-vflIlGysZ.png"
        $spec_file4 = "keep-your-photos-safe-vflZe9PHC.png"

    condition:
        // look for the ZIP header and all
        uint32(0) == 0x04034b50 and
        $local_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
