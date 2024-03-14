rule PK_ING_DE : ING
{
    meta:
        description = "Phishing Kit impersonating ING bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-03-08"
        comment = "Phishing Kit - ING bank - 'delogin directory, DE language'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "access"
        $spec_dir2 = "delogin"

        $spec_file1 = "itan.php"
        $spec_file2 = "firma.php"
        $spec_file3 = "visitors.html"
        $spec_file4 = "sus.gif"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
