rule PK_Netflix_blackforce : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-22"
        comment = "Phishing Kit - Netflix - 'Coded By Root_Dr'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "botActBan"
        $spec_dir1 = "config"
        $spec_dir2 = "prevents"
        // specific file found in PhishingKit
        $spec_file = "visitors.html"
        $spec_file2 = "banIpAct.php"
        $spec_file3 = "crawler-user-agents.json"
        $spec_file4 = "captcha.php"
        $spec_file5 = "ngif.gif"
        $spec_file6 = "insert.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
