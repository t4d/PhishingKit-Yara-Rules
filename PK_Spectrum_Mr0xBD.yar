rule PK_Spectrum_Mr0xBD : Spectrum
{
    meta:
        description = "Phishing Kit impersonating Spectrum"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-09-28"
        comment = "Phishing Kit - Spectrum - 'Mr0xBD'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "7QIRuTV1ld.php"
        $spec_file2 = "bank.html"
        $spec_file3 = "done.html"
	    $spec_file4 = "process-bank.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}

