rule PK_PNC_eo : PNC
{
    meta:
        description = "Phishing Kit impersonating PNC online bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-11-01"
        comment = "Phishing Kit - PNC - 'newrepnceo'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "database"
        $spec_dir1 = "system"
        $spec_dir2 = "third_party"
        // specific file found in PhishingKit
        $spec_file = "blocker.php"
        $spec_file2 = "cazanova_helper.php"
        $spec_file3 = "authen.php"
        $spec_file4 = "sitekey.php"
        $spec_file5 = "2134651.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
