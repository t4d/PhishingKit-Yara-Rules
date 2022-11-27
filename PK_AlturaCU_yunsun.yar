rule PK_AlturaCU_yunsun : AlturaCU
{
    meta:
        description = "Phishing Kit impersonating Robins Altura Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-11-10"
        comment = "Phishing Kit - AlturaCU - 'TELEGRAM : @Yun_Sun'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directories found in PhishingKit
        $spec_dir = "anti__boot"
        $spec_dir1 = "js"
        // specific file found in PhishingKit
        $spec_file = "access.php"
        $spec_file2 = "loading-3.php"
        $spec_file3 = "anti8.php"
        $spec_file4 = "test.css"
        $spec_file5 = "loogo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
