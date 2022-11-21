rule PK_RBFCU_mky : RBFCU
{
    meta:
        description = "Phishing Kit impersonating Randolph-Brooks Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-11-09"
        comment = "Phishing Kit - RBFCU - 'CREATED BY @MKYDAGOAT'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directories found in PhishingKit
        $spec_dir = "botfucker"
        $spec_dir1 = "Os"
        // specific file found in PhishingKit
        $spec_file = "securityq.php"
        $spec_file2 = "ncua.png"
        $spec_file3 = "crawlerdetect.php"
        $spec_file4 = "useragent.dat"
        $spec_file5 = "SpamReferrers.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
