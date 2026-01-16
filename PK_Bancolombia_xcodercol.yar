rule PK_Bancolombia_xcodercol : Bancolombia
{
    meta:
        description = "Phishing Kit impersonating Bancolombia"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-01-16"
        comment = "Phishing kit impersonating Bancolombia - 'Desarrollado por XcoderCol, Inc.'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "portal"
        $spec_dir1 = "control"
        $spec_file = "logosesca.png"
        $spec_file2 = "presence_ping.php"
        $spec_file3 = "tcverification.php"
        $spec_file4 = "923.php"
        $spec_file5 = "timbre12.mp3"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
