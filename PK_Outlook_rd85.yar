rule PK_Outlook_rd85 : Outlook
{
    meta:
        description = "Phishing Kit impersonating Microsoft Outlook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-08"
        comment = "Phishing Kit - Outlook - RD85"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file2 = "next.php"
        $spec_file3 = "email.php"
        $spec_file4 = "index.html"
        $spec_file5 = "microsoft_logo.svg"
        $spec_file6 = "key.svg"
        $spec_file7 = "ol.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        // check for files
        all of ($spec_file*)
}
