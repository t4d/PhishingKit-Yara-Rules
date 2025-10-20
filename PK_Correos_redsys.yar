rule PK_Correos_redsys : Correos
{
    meta:
        description = "Phishing Kit impersonating Correos Argentina"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2025-10-11"
        comment = "Phishing Kit - Correos - Redsys_files directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Redsys_files"
        $spec_dir2 = "Seleccione medio de pago_fichiers"
        $spec_dir3 = "Venta_fichiers"
        $spec_file1 = "codeerror2.php"
        $spec_file2 = "Seleccione_gracias.php"
        $spec_file3 = "Redsys.html"
        $spec_file4 = "logo-correos-tpv_2.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
