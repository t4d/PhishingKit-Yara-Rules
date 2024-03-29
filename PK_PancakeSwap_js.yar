rule PK_PancakeSwap_js : PancakeSwap
{
    meta:
        description = "Phishing Kit impersonating PancakeSwap.finance"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-09"
        comment = "Phishing Kit - PancakeSwap - mostly JS"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "_next"
        $spec_dir2 = "oYJ4s4eRSIbPMqWPptiGc"
        $spec_dir3 = "home"

        // specific file found in PhishingKit
        $spec_file = "popup-6.css"
        $spec_file2 = "_ssgManifest.js"
        $spec_file3 = "7d58cdd3-1068-4b09-a428-7a9c5bd94af4.js"
        $spec_file4 = "wallet-connect-v3.js"
        $spec_file5 = "phishing-warning-bunny.webp"
        $spec_file6 = "rabby-rainbow.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
