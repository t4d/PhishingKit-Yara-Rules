rule PK_Outlook_uy : Outlook
{
    meta:
        description = "Phishing Kit impersonating Microsoft Outlook"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-10-04"
        comment = "Phishing Kit - Outlook - contain 'uy' dir. name"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "uy"
        $spec_file2 = "send.php"
        $spec_file3 = "Outlook.htm"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        // check for files
        all of ($spec_file*)
}
