rule PK_IdahoCentralCU_iris : Idaho Central Credit Union
{
    meta:
        description = "Phishing Kit impersonating Idaho Central Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-09-26"
        comment = "Phishing Kit - Idaho Central Credit Union - contain 'iris' directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "idaho"
        $spec_dir1 = "myebranch"
        $spec_dir2 = "iris"
        // specific files found in PhishingKit
        $spec_file1 = "process3.php"
        $spec_file2 = "telegram.php"
        $spec_file3 = "grabber.php"
        $spec_file4 = "iccu_bg.jpg"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
