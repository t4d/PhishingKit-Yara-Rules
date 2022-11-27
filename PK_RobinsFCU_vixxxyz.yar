rule PK_RobinsFCU_vixxxyz : RobinsFCU
{
    meta:
        description = "Phishing Kit impersonating Robins Financial Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-11-10"
        comment = "Phishing Kit - RobinsFCU - 'Scama By @VixxxyZ'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directories found in PhishingKit
        $spec_dir = "admin"
        $spec_dir1 = "VixxxyZ"
        // specific file found in PhishingKit
        $spec_file = "VixxxYZ_purpled.php"
        $spec_file2 = "vixxxYZ==.ini"
        $spec_file3 = "trulogo_horz-trupurple.png"
        $spec_file4 = "vixxxyz0.css"
        $spec_file5 = "vixxxyz5.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
