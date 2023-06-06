rule PK_QatarPost_spy : QatarPost
{
    meta:
        description = "Phishing Kit impersonating Qatar Post"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-04"
        comment = "Phishing Kit - QatarPost - using a spy.php file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "ar"
        $spec_dir1 = "inc"
        $spec_dir2 = "bots"
        // specific file found in PhishingKit
        $spec_file = "spy.php"
        $spec_file2 = "botMother.php"
        $spec_file3 = "date.php"
        $spec_file4 = "sms.php"
        $spec_file5 = "bv.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
