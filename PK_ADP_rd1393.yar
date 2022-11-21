rule PK_ADP_rd1393 : ADP
{
    meta:
        description = "Phishing Kit impersonating ADP.com"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-16"
        comment = "Phishing Kit - ADP - RD1393"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "em.html"
        $spec_file2 = "next.php"
        $spec_file3 = "main.816072d9.chunk.css"
        $spec_file4 = "logo-adp-fy19.299df579.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
