rule PK_Generic_goodlogs : goodlogs_generic
{
    meta:
        description = "Phishing Kit - Generic email credentials stealer"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-03-12"
        comment = "Phishing Kit - Generic - 'From: G@@DLogs'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "koreane.php"
        $spec_file2 = "dom.php"
        $spec_file4 = "trytti.php"
        $spec_file5 = "FormDutala.txt"
        $spec_file6 = "hiworks.png"
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}
