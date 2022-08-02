rule PK_MicrosoftDocs_fudpages : Microsoft
{
    meta:
        description = "Phishing Kit impersonating Microsoft Docs"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-26"
        comment = "Phishing Kit - Microsoft - '- FUDPAGEs [.] RU -'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "assets"

        // specific file found in PhishingKit
        $spec_file = "index-2.php"
        $spec_file2 = "index2.php"
        $spec_file3 = "processor.php"
        $spec_file4 = "theDocs.all.min.css"
        $spec_file5 = "word.png"
        $spec_file6 = "theDocs.all.min.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
