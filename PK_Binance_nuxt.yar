rule PK_Binance_nuxt : Binance
{
    meta:
        description = "Phishing Kit impersonating Binance"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-31"
        comment = "Phishing Kit - Binance - using '_nuxt' directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "_nuxt"
        $spec_dir2 = "builds"       
        $spec_file1 = "C5M-ywlo.js"
        $spec_file2 = "cfg.js"
        $spec_file3 = "bootstrap-icons.BOrJxbIo.woff"
        $spec_file4 = "error-404.CoZKRZXM.css"
        $spec_file5 = "b.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
