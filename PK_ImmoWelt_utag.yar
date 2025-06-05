rule PK_ImmoWelt_utag : ImmoWelt
{
    meta:
        description = "Phishing Kit impersonating ImmoWelt (AVIV Group)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-28"
        comment = "Phishing Kit - ImmoWelt - using Tealium Universal tag (utag.js)"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Login_files"
        $spec_dir2 = "identitat_files"
        $spec_file1 = "ionospassword.html"
        $spec_file2 = "do3.php"
        $spec_file3 = "cross-domain-bridge.htm"
        $spec_file4 = "Telefoncode.html"
        $spec_file5 = "logo_immowelt.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
