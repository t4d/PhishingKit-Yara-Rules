rule PK_PNC_mky : PNC
{
    meta:
        description = "Phishing Kit impersonating PNC online bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-10-01"
        comment = "Phishing Kit - PNC - 'CREATED BY MkY'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "CrawlerDetect"
        $spec_dir1 = "file"
        $spec_dir2 = "Os"
        // specific file found in PhishingKit
        $spec_file = "crawlerdetect.php"
        $spec_file2 = "securityq.php"
        $spec_file3 = "c20kdg.php"
        $spec_file4 = "Send.php"
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
