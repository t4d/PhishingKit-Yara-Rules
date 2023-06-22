rule PK_Optus_ard8no : Optus
{
    meta:
        description = "Phishing Kit impersonating Optus (webmail.optusnet.com.au)"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-19"
        comment = "Phishing Kit - Optus - '+ Made By RED@_@X +'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "opts"
        $spec_dir2 = "files"

        $spec_file1 = "billing.php"
        $spec_file2 = "code.php"
        $spec_file3 = "sms1.php"
        $spec_file4 = "fin.php"
        $spec_file5 = "sc.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
