rule PK_SwissPost_draflam : SwissPost
{
    meta:
        description = "Phishing Kit impersonating Swiss Post"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-20"
        comment = "Phishing Kit - Swiss Post - Containing DRAFLAM directory"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "DRAFLAM"
        $spec_dir2 = "siftA"
        $spec_dir3 = "X911"
        // specific file found in PhishingKit
        $spec_file = "COUNTRY.php"
        $spec_file2 = "TELEGRMAT.php"
        $spec_file3 = "911.php"
        $spec_file4 = "Loading.php"
        $spec_file5 = "DISCOVER.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
