rule PK_AXA_darknet : AXA
{
    meta:
        description = "Phishing Kit impersonating AXA CH"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2026-06-10"
        comment = "Phishing Kit - AXA - 'Collected by: DarkNet_v1'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "victims"
        $spec_dir2 = "res"
        $spec_file = "cho.php"
        $spec_file2 = "sms.php"
        $spec_file3 = "cc.css"
        $spec_file4 = "ays.png"
        $spec_file5 = "chf.gif"

    condition:
        uint32(0) == 0x04034b50 and 
        $zip_file and 
        all of ($spec_file*) and
        all of ($spec_dir*)
}
