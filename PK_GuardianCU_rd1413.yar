rule PK_GuardianCU_rd1413 : Guardian_Credit_Union
{
    meta:
        description = "Phishing Kit - RD1413 - impersonating Guardian Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-10-14"
        comment = "Phishing Kit - Guardian Credit Union - RD1413"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir1 = "images"
        // specific file found in PhishingKit
        $spec_file = "em.html"
        $spec_file2 = "quest.html"
        $spec_file3 = "next.php"
        $spec_file4 = "email.php"
        $spec_file5 = "Default__98O5UELFY81_Default.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
