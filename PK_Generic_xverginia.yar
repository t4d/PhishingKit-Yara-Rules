rule PK_Generic_xverginia : Xverginia
{
    meta:
        description = "Xverginia Phishing Kit"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-06"
        comment = "Phishing Kit - Xverginia"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "build"
        $spec_dir2 = "turnstile"
        $spec_dir3 = "phishlets"
        $spec_file1 = "xverginia"
        $spec_file2 = "table.html"
        $spec_file3 = "fallback.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
