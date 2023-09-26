rule PK_Naver_unknown : Naver
{
    meta:
        description = "Phishing Kit impersonating Naver Corp."
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-22"
        comment = "Phishing Kit - Naver - 'Created BY Unknown'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "nvv.php"
        $spec_file2 = "esss.php"
        $spec_file3 = "next.php"
        $spec_file4 = "favicon.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
