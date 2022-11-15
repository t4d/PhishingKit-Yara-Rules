rule PK_Netflix_yochi : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-07"
        comment = "Phishing Kit - Netflix - 'SCAM PAGE NETFLIX #By YOCHI, WORK HARD DREAM B!G'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "admin"
        $spec_dir2 = "fad58"
        // specific file found in PhishingKit
        $spec_file = "proc.php"
        $spec_file2 = "infile.php"
        $spec_file3 = "upp.php"
        $spec_file4 = "nf-icon-v1-93.ttf"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
