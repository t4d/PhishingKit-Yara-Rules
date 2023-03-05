rule PK_Postbank_memoryerror : Postbank
{
    meta:
        description = "Phishing Kit impersonating Postbank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-02"
        comment = "Phishing Kit - Postbank - 'Main Author: MemoryError'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "victims"
        $spec_dir1 = "3-D Secure_files"
        $spec_dir2 = "Loginloading_files"
        // specific file found in PhishingKit
        $spec_file = "LoginPASS.html"
        $spec_file2 = "3-D Secure.html"
        $spec_file3 = "botMother.php"
        $spec_file4 = "0om4.php"
        $spec_file5 = "account.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
