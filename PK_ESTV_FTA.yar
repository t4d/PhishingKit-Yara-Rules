rule PK_ESTV_FTA : ESTV
{
    meta:
        description = "Phishing Kit impersonating FTA/ESTV, Swiss Federal Tax Administration"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-10-13"
        comment = "Phishing Kit - FTA/ESTV"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_dir2 = "stats"
        $spec_file = "stats.json"
        $spec_file2 = "index-right-content.avif"
        $spec_file3 = "swiss-logo-flag.svg"
        $spec_file4 = "script.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
