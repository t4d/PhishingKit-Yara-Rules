rule PK_Citizens_snickyninja : CitizensBank
{
    meta:
        description = "Phishing Kit impersonating Citizens Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7198548331063640064"
        date = "2024-05-27"
        comment = "Phishing Kit - CitizensBank - 'SNICKYNINJA'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        $spec_dir = "darkx"
        $spec_dir2 = "emailauth"
        $spec_dir3 = "dist"
        $spec_file1 = "personal.php"
        $spec_file2 = "question.php"
        $spec_file3 = "jquery.mask.js"
        $spec_file4 = "JK_1027.jpg"
        $spec_file5 = "additional-methods.min.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
       $local_file and 
       all of ($spec_dir*) and 
       all of ($spec_file*)
}
