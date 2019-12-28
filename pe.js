// PE file parser

(function () {
    function h(n) {
        var str = n.toString(16).toUpperCase();
        while (str.length < 8) {
            str = "0" + str;
        }
        return str;

    }

    var file = null;
    function pe_parse(raw, verbose) {
        var ptr = 0;
        // ---------------------------
        //     DOS HEADER
        // ---------------------------
        if (raw[0] !== 0x4d && raw[1] !== 0x5a) {
            throw new Error("Incorrect magic number?!");
        }
        /*
         var trash1 = raw[2] | (raw[3] << 8); // number of bytes in the last page.
         var trash2 = raw[4] | (raw[5] << 8); // number of whole/partial pages.
         var trash3 = raw[6] | (raw[7] << 8); // number of entries in the relocation
         table.
         var trash4 = raw[8] | (raw[9] << 8); // number of paragraphs taken up by the
         header.
         var trash5 = raw[0x0a] | (raw[0x0b] << 8); // minimum allocation
         var trash6 = raw[0x0c] | (raw[0x0d] << 8); // maximum allocation
         var trash7 = raw[0x0e] | (raw[0x0f] << 8); // Initial SS
         var trash8 = raw[0x10] | (raw[0x11] << 8); // Initial SP
         var trash9 = raw[0x12] | (raw[0x13] << 8); // checksum
         var trashA = raw[0x14] | (raw[0x15] << 8); // Initial IP
         var trashB = raw[0x16] | (raw[0x17] << 8); // Initial CS
         var trash5 = raw[0x18] | (raw[0x19] << 8); // Relocation Table offset
         var trash5 = raw[0x1A] | (raw[0x1B] << 8); // overlay
         */
        var peheader_offset = raw[0x3c] | (raw[0x3d] << 8) | (raw[0x3e] << 16) | (raw[0x3F] << 24);
        ptr = peheader_offset;
        if (verbose)
            log("PE Header offset: " + h(peheader_offset));
        // Assume PE header is there(
        ptr += 4;

        var machine = raw[ptr++] | (raw[ptr++] << 8);
        if (verbose)
            console.info("Machine: " + h(machine) + ", i386");
        if (machine !== 0x14C) {
            throw new Error("Can only translate i386 binaries.");
        }
        var ph = new PEHeader();
        ph.sectionNumber = raw[ptr++] | (raw[ptr++] << 8);
        if (verbose)
            log("Number of sections: " + h(ph.sectionNumber));
        ph.timeDateStamp = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Time/Date Stamp: " + h(ph.timeDateStamp));
        ph.symTab = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Symbol Table pointer: " + h(ph.symTab));
        ph.symbolNumber = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Number of symbols: " + h(ph.symbolNumber));
        ph.sizeofOptHeader = raw[ptr++] | (raw[ptr++] << 8);
        if (verbose)
            log("Optional Header size: " + h(ph.sizeofOptHeader));
        ph.characteristics = raw[ptr++] | (raw[ptr++] << 8);
        if (verbose)
            log("Characteristics: " + h(ph.characteristics));
        ph.parseCharacteristics();
        ph.magic = raw[ptr++] | (raw[ptr++] << 8);
        if (ph.magic !== 0x010B) {
            throw new Error("The executable file is not a PE32");
        }
        if (verbose)
            log("Magic: " + h(ph.magic));
        ph.linkerVersion = raw[ptr++] | (raw[ptr++] << 8);
        if (verbose)
            log("Linker version: " + ph.linkerVersion);
        ph.sizeofCode = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Size of code: " + h(ph.sizeofCode));
        ph.sizeofInitData = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Size of initialized data: " + h(ph.sizeofInitData));
        ph.sizeofUninitData = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Size of uninitialized data: " + h(ph.sizeofUninitData));
        ph.entryPoint = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Entry point address: " + h(ph.entryPoint));
        ph.baseOfCode = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Base of code: " + h(ph.baseOfCode));
        ph.baseOfData = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Base of data: " + h(ph.baseOfData));
        ph.imageBase = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Image base: " + h(ph.imageBase));
        ph.sectionAlignment = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Section alignment: " + h(ph.sectionAlignment));
        ph.fileAlignment = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("File alignment: " + h(ph.fileAlignment));
        ph.operatingSystemVersion = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("OS version: " + h(ph.operatingSystemVersion));
        ph.imageVersion = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Image version: " + h(ph.imageVersion));
        ph.subsystemVersion = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Subsystem version: " + h(ph.subsystemVersion));
        ph.win32versionValue = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Win32 Version Value: " + h(ph.win32versionValue));
        ph.sizeofImage = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Size of PE image: " + h(ph.sizeofImage));
        ph.sizeofHeaders = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Size of headers: " + h(ph.sizeofHeaders));
        ph.checksum = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Checksum: " + h(ph.checksum));
        ph.subsystem = raw[ptr++] | (raw[ptr++] << 8);
        if (verbose)
            log("Subsystem: " + h(ph.subsystem));
        ph.dllCharacteristics = raw[ptr++] | (raw[ptr++] << 8);
        if (verbose)
            log("DLL Characteristics: " + h(ph.dllCharacteristics));
        ph.sizeofStackReserve = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Size of Stack Reserve: " + h(ph.sizeofStackReserve));
        ph.sizeofStackCommit = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Size of Stack Commit: " + h(ph.sizeofStackCommit));
        ph.sizeofHeapReserve = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Size of Heap Reserve: " + h(ph.sizeofHeapReserve));
        ph.sizeofHeapCommit = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Size of Heap Commit: " + h(ph.sizeofHeapCommit));
        ph.loaderFlags = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Loader flags: " + h(ph.loaderFlags));
        ph.numberOfData = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
        if (verbose)
            log("Number of Data Directories: " + h(ph.numberOfData));
        if (verbose)
            log("-- Directory Entries --");
        ph.exportTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.exportTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Export Table RVA: " + h(ph.exportTable.rva));
            log("Export Table Size: " + h(ph.exportTable.size));
        }

        ph.importTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.importTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Import Table RVA: " + h(ph.importTable.rva));
            log("Import Table Size: " + h(ph.importTable.size));
        }

        ph.resourceTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.resourceTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Resource Table RVA: " + h(ph.resourceTable.rva));
            log("Resource Table Size: " + h(ph.resourceTable.size));
        }

        ph.exceptionTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.exceptionTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Exception Table RVA: " + h(ph.exceptionTable.rva));
            log("Exception Table Size: " + h(ph.exceptionTable.size));
        }

        ph.certificateTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.certificateTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Certificate Table RVA: " + h(ph.certificateTable.rva));
            log("Certificate Table Size: " + h(ph.certificateTable.size));
        }

        ph.relocationTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.relocationTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Relocation Table RVA: " + h(ph.relocationTable.rva));
            log("Relocation Table Size: " + h(ph.relocationTable.size));
        }

        ph.debugData.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.debugData.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Debug Data RVA: " + h(ph.debugData.rva));
            log("Debug Data Table Size: " + h(ph.debugData.size));
        }

        ph.archData.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.archData.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Architecture-Specifc Data RVA: " + h(ph.archData.rva));
            log("Architecture-Specifc Data Table Size: " + h(ph.archData.size));
        }

        ph.machineValue.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.machineValue.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Global Pointer Register RVA: " + h(ph.machineValue.rva));
            log("Global Pointer Register Table Size: " + h(ph.machineValue.size));
        }

        ph.TLSTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.TLSTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("TLS Table RVA: " + h(ph.TLSTable.rva));
            log("TLS Table Size: " + h(ph.TLSTable.size));
        }

        ph.loadConfigurationTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.loadConfigurationTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Load Configuration Table RVA: " + h(ph.loadConfigurationTable.rva));
            log("Load Configuration Table Size: " + h(ph.loadConfigurationTable.size));
        }

        ph.boundImportTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.boundImportTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Bound Import Table RVA: " + h(ph.boundImportTable.rva));
            log("Bound Import Table Size: " + h(ph.boundImportTable.size));
        }

        ph.importAddressTable.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.importAddressTable.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Import Address Table RVA: " + h(ph.importAddressTable.rva));
            log("Import Address Table Size: " + h(ph.importAddressTable.size));
        }

        ph.delayImportDescriptor.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.delayImportDescriptor.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Delay Import Descriptor RVA: " + h(ph.delayImportDescriptor.rva));
            log("Delay Import Descriptor Size: " + h(ph.delayImportDescriptor.size));
        }

        ph.COMRuntimeHeader.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.COMRuntimeHeader.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));
        if (verbose) {
            log("Component Object Model Runtime Header RVA: " + h(ph.COMRuntimeHeader.rva));
            log("Component Object Model Runtime Header Size: " + h(ph.COMRuntimeHeader.size));
        }

        ph.__RESERVED__.setvaddr(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24), ph.imageBase);
        ph.__RESERVED__.setsize(raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24));

        for (var i = 0; i < ph.sectionNumber; i++) {
            var txt = "";
            for (var j = 0; j < 8; j++) {// Apparently, all strings are 8 chars or under.
                if (raw[ptr]) {
                    txt += String.fromCharCode(raw[ptr++]);
                } else {
                    ptr++;
                }
            }
            var virtualSize = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
            if (verbose)
                log("Section " + txt + " virtual size: " + h(virtualSize));
            var virtualAddress = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
            if (verbose)
                log("Section " + txt + " virtual address: " + h(virtualAddress));
            var sizeofRaw = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
            if (verbose)
                log("Section " + txt + " size (raw): " + h(sizeofRaw));
            var pointerToRaw = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
            if (verbose)
                log("Section " + txt + " pointer to raw data: " + h(pointerToRaw));
            var pointerToRelocations = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
            if (verbose)
                log("Section " + txt + " pointer to relocations: " + h(pointerToRelocations));
            var pointerToLnNos = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
            if (verbose)
                log("Section " + txt + " pointer to line numbers: " + h(pointerToLnNos));
            var noRelocations = raw[ptr++] | (raw[ptr++] << 8);
            if (verbose)
                log("Section " + txt + " number of relocations: " + h(noRelocations));
            var noLnNos = raw[ptr++] | (raw[ptr++] << 8);
            if (verbose)
                log("Section " + txt + " number of line numbers: " + h(noLnNos));
            var characteristics = (raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24)) >>> 0;
            if (verbose)
                log("Section " + txt + " characteristics: " + h(characteristics));

            ph.sectionHeaders.push(new SectionHeader(txt, virtualSize, virtualAddress, sizeofRaw, pointerToRaw, pointerToRelocations, characteristics));
        }
        // Save Raw data
        ph.raw = raw;

        // Address in file = (import_rva - section_rva) + section_raw_ptr;

        // Get import data.
        {
            var i_addr = 0, i_size = 0;
            var impt = ph.importTable;
            i_size = impt.size;
            var impt_rva = (impt.vaddr & ~ph.imageBase);
            var section_raw_ptr = 0, section;
            // Get section where data resides
            var section = null;
            for (var i = 0; i < ph.sectionHeaders.length; i++) {
                // Alias.
                var sh = ph.sectionHeaders[i];
                if (((sh.virtualAddress + sh.virtualSize) >= impt_rva) && (sh.virtualAddress <= impt_rva)) {
                    section_raw_ptr = ph.sectionHeaders[i].pointertoRaw;
                    section = sh;
                }
            }
            if (section) {
                var section_rva = section.virtualAddress;
                var final_addr = (impt_rva - section_rva) + section_raw_ptr;
                i_addr = final_addr;
                if (verbose)
                    log(" -- Imports -- ");
                var imports = [];
                {
                    ptr = i_addr;
                    if (i_addr) {
                        var j = i_addr;
                        //for (var j = i_addr; ptr < j + i_size; ) {
                        for (; ;) {
                            // Sometimes (i.e. radare2 test binaries), an import table can have a length of
                            // ZERO but functions will still get imported
                            //log(imports);
                            // rva import lookup table
                            var a = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // time date stamp
                            var b = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // forwarder chain
                            var c = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // rva module name
                            var d = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // rva import address table ("thunk")
                            var e = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            if (!a && !b && !c && !d && !e || (a && !b && !c && !d && !e)) {
                                break;
                                // empty structure, signals the end of the import table.
                            }
                            //log(h(a), h(b), h(c), h(d), h(e));
                            // Find name
                            var temp_ptr = ptr;
                            ptr = ph.findFileAddress(d);
                            var name = "";
                            while (raw[ptr] !== 0) {
                                name += String.fromCharCode(raw[ptr++]);
                            }

                            if (verbose) {
                                log("DLL Name: " + name + "");
                                log("    RVA of Import lookup Table: " + h(a));
                                log("    Time Date Stamp: " + h(b));
                                log("    Forwarder Chain: " + h(c));
                                log("    RVA module name: " + h(d));
                                log("    RVA import address table: " + h(e));
                                log("    Imported functions: ");
                            }
                            ptr = temp_ptr;
                            var funcs = [];
                            var temp = {
                                dllname: name,
                                rva_import_lookup_table: a,
                                time_date_stamp: b,
                                forwarder_chain: c,
                                rva_module_name: d,
                                rva_import_address_table: e,
                                funcs: funcs,
                                ordinal: -1
                            };
                            temp_ptr = ptr;
                            ptr = ph.findFileAddress(a);
                            var i = 0;
                            while (true) {
                                if (temp > 100) {
                                    throw "end";
                                }
                                var number = (raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24)) >>> 0;
                                if (number == 0) {
                                    break;
                                }
                                if (number & 0x80000000) {
                                    // Ordinal
                                    temp.ordinal = number ^ 0x80000000;
                                    // Get rid of number.
                                    break;
                                }
                                var save_ = ptr;
                                // save
                                ptr = ph.findFileAddress(number >>> 0);
                                var ident = raw[ptr++] | (raw[ptr++] << 8);
                                // get ASCIIZ string.
                                var name = "";
                                while (raw[ptr] !== 0) {
                                    name += String.fromCharCode(raw[ptr++]);
                                }
                                ptr = save_;

                                if (verbose) {
                                    log("        " + name + "@" + h(number));
                                }

                                funcs.push({
                                    name: name,
                                    vaddr: number,
                                    ident: ident,
                                    rva: e + (i * 4)
                                });
                                i++;
                            }
                            ptr = temp_ptr;
                            imports.push(temp);
                            if (i_size && !(ptr < j + i_size)) {
                                break;
                            }
                        }
                    }
                }
                ph.imports = imports;
            }
        } {
            // Find exports
            var e_addr = 0, e_size = 0;
            var expt = ph.exportTable;
            e_size = expt.size;
            var expt_rva = (expt.vaddr & ~ph.imageBase);
            var section_raw_ptr = 0, section;
            // Get section where data resides
            var section = null;
            for (var i = 0; i < ph.sectionHeaders.length; i++) {
                // Alias.
                var sh = ph.sectionHeaders[i];
                if (((sh.virtualAddress + sh.virtualSize) >= expt_rva) && (sh.virtualAddress <= expt_rva)) {
                    section_raw_ptr = ph.sectionHeaders[i].pointertoRaw;
                    section = sh;
                }
            }
            if (section) {
                var section_rva = section.virtualAddress;
                var final_addr = (expt_rva - section_rva) + section_raw_ptr;
                e_addr = final_addr;
                if (verbose)
                    log(" -- Exports -- ");
                var exports = [];
                {
                    ptr = e_addr;

                    if (e_addr) {
                        var j = e_addr;
                        do {
                            var characteristics = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            var timeDateStamp = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            var majorVersion = raw[ptr++] | (raw[ptr++] << 8);
                            var minorVersion = raw[ptr++] | (raw[ptr++] << 8);
                            // nameptr
                            var a = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // ordinal bias
                            var b = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // total # of functions
                            var c = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // number of names exported
                            var d = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // addr of funcs
                            var e = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // addr of names
                            var f = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            // addr of name ordinals
                            var g = raw[ptr++] | (raw[ptr++] << 8) | (raw[ptr++] << 16) | (raw[ptr++] << 24);
                            if (!a && !b && !c && !d && !e && !f && !g || (a && !b && !c && !d && !e && !f && !g)) {
                                break;
                                // empty structure, signals the end of the import table.
                            }
                            // Find name
                            var temp_ptr = ptr;
                            ptr = ph.findFileAddress(a);
                            var name = "";
                            while (raw[ptr] !== 0) {
                                name += String.fromCharCode(raw[ptr++]);
                            }
                            if (verbose) {
                                log("Characteristics: " + h(characteristics));
                                log("Time Date Stamp: " + h(timeDateStamp));
                                log("Major version: " + h(majorVersion));
                                log("Minor version: " + h(minorVersion));
                                log("");
                                log("Name of module: " + name);
                                log("    Name of bias of ordinals: " + h(b));
                                log("    Total number of functions exported: " + h(c));
                                log("    Total number of NAMED functions exported: " + h(d));
                                log("    Address of functions: " + h(e));
                                log("    Address of names: " + h(f));
                                log("    Address of name ordinals " + h(g));
                            }
                            var addr_ptr = ph.findFileAddress(e);
                            var addr_name_ptr = ph.findFileAddress(f);
                            for (var i = 0; i < d; i++) {
                                var addr = raw[addr_ptr++] | (raw[addr_ptr++] << 8) | (raw[addr_ptr++] << 16) | (raw[addr_ptr++] << 24);
                                addr |= ph.imageBase | addr;
                                var name = raw[addr_name_ptr++] | (raw[addr_name_ptr++] << 8) | (raw[addr_name_ptr++] << 16) | (raw[addr_name_ptr++] << 24);
                                ptr = ph.findFileAddress(name);
                                var fname = "";
                                while (raw[ptr] !== 0) {
                                    fname += String.fromCharCode(raw[ptr++]);
                                }
                                if (verbose)
                                    log("        " + fname + "@" + h(addr));
                                exports.push({
                                    name: fname,
                                    vaddr: addr
                                });
                            }
                        } while (0);
                    }
                }
                ph.exports = exports;
            }
        }
        if (verbose)
            log(" -- Finished parsing PE file --");
        return ph;
    }

    /**
     * @constructor
     */
    function PEHeader() {
        this.raw = null;
        this.sectionNumber = 0;
        this.timeDateStamp = 0;
        this.symTab = 0;
        this.symbolNumber = 0;
        this.sizeofOptHeader = 0;
        this.characteristics = 0;
        this.characteristics_obj = {
            "Relocation information is stripped from the file": false,
            "The file is executable": false,
            "Line numbers are stripped from the file": false,
            "Local symbols are stripped from the file": false,
            "Agressively trim the working set": false,
            "The application can handle addresses larger than 2 GB": false,
            "Bytes of words are reversed": false,
            "Computer supports 32-bit words": false,
            "Debugging information is stored separately in a .dbg file": false,
            "If the image is on removable media, copy and run from the swap file": false,
            "If the image is on the network, copy and run from the swap file": false,
            "The file is a system file": false,
            "The file is a DLL": false,
            "File should not be run on multiprocessing (SMP) computers": false,
            "Bytes of the word are reversed": false
        };
        this.magic = 0;
        this.linkerVersion = 0;
        this.sizeofCode = 0;
        this.sizeofInitData = 0;
        this.sizeofUninitData = 0;
        this.entryPoint = 0;
        this.baseOfCode = 0;
        this.imageBase = 0;
        this.sectionAlignment = 0;
        this.fileAlignment = 0;
        this.operatingSystemVersion = 0;
        this.imageVersion = 0;
        this.subsystemVersion = 0;
        this.win32versionValue = 0;
        this.sizeofImage = 0;
        this.sizeofHeaders = 0;
        this.checksum = 0;
        this.subsystem = 0;
        this.dllCharacteristics = 0;
        this.sizeofStackReserve = 0;
        this.sizeofStackCommit = 0;
        this.sizeofHeapReserve = 0;
        this.sizeofHeapCommit = 0;
        this.loaderFlags = 0;
        this.numberofData = 0;

        // Data directories

        this.exportTable = new PEDirectoryEntry(this.imageBase);
        this.importTable = new PEDirectoryEntry(this.imageBase);
        this.resourceTable = new PEDirectoryEntry(this.imageBase);
        this.exceptionTable = new PEDirectoryEntry(this.imageBase);
        this.certificateTable = new PEDirectoryEntry(this.imageBase);
        this.relocationTable = new PEDirectoryEntry(this.imageBase);
        this.debugData = new PEDirectoryEntry(this.imageBase);
        this.archData = new PEDirectoryEntry(this.imageBase);
        this.machineValue = new PEDirectoryEntry(this.imageBase);
        this.TLSTable = new PEDirectoryEntry(this.imageBase);
        this.loadConfigurationTable = new PEDirectoryEntry(this.imageBase);
        this.boundImportTable = new PEDirectoryEntry(this.imageBase);
        this.importAddressTable = new PEDirectoryEntry(this.imageBase);
        this.delayImportDescriptor = new PEDirectoryEntry(this.imageBase);
        this.COMRuntimeHeader = new PEDirectoryEntry(this.imageBase);

        this.__RESERVED__ = new PEDirectoryEntry(this.imageBase);
        // reserved

        // Section headers
        this.sectionHeaders = [];
        this.imports = [];
        this.exports = [];

        // Number of times referred to (see cpu.js)
        this.references = 0;
    }

    PEHeader.prototype.findFileAddress = function (rva) {
        var section_raw_ptr = 0, section;
        for (var i = 0; i < this.sectionHeaders.length; i++) {
            var sh = this.sectionHeaders[i];
            if (((sh.virtualAddress + sh.virtualSize) > rva) && (sh.virtualAddress < rva)) {
                section_raw_ptr = this.sectionHeaders[i].pointertoRaw;
                section = sh;
            }
        }
        if (!section) {
            console.error("Section not found: RVA = " + h(rva));
            throw new Error("Section not found!");
        }
        var section_rva = section.virtualAddress;
        var final_addr = (rva - section_rva) + section_raw_ptr;
        return final_addr;
    };

    PEHeader.prototype.parseCharacteristics = function () {
        var t = this.characteristics;
        if (t & 1) {
            this.characteristics_obj["Relocation information is stripped from the file"] = true;
        }
        if (t & 2) {
            this.characteristics_obj["The file is executable"] = true;
        }
        if (t & 4) {
            this.characteristics_obj["Line numbers are stripped from the file"] = true;
        }
        if (t & 8) {
            this.characteristics_obj["Local symbols are stripped from the file"] = true;
        }
        if (t & 0x10) {
            this.characteristics_obj["Agressively trim the working set"] = true;
        }
        if (t & 0x20) {
            this.characteristics_obj["The application can handle addresses larger than 2 GB"] = true;
        }
        if (t & 0x80) {
            this.characteristics_obj["Bytes of words are reversed"] = true;
        }
        if (t & 0x100) {
            this.characteristics_obj["Computer supports 32-bit words"] = true;
        }
        if (t & 0x200) {
            this.characteristics_obj["Debugging information is stored separately in a .dbg file"] = true;
        }
        if (t & 0x400) {
            this.characteristics_obj["If the image is on removable media, copy and run from the swap file"] = true;
        }
        if (t & 0x800) {
            this.characteristics_obj["If the image is on the network, copy and run from the swap file"] = true;
        }
        if (t & 0x1000) {
            this.characteristics_obj["The file is a system file"] = true;
        }
        if (t & 0x2000) {
            this.characteristics_obj["The file is a DLL"] = true;
        }
        if (t & 0x4000) {
            this.characteristics_obj["File should not be run on multiprocessing (SMP) computers"] = true;
        }
        if (t & 0x8000) {
            this.characteristics_obj["Bytes of the word are reversed"] = true;
        }
    };

    PEHeader.prototype.getSectionInfo = function (i) {
        return this.sectionHeaders[i];
    };
    PEHeader.prototype.getSectionInfoByName = function (n) {
        for (var i = 0; i < this.sectionHeaders.length; i++) {
            if (this.sectionHeaders[i].name === n) {
                return this.getSectionInfo(i);
            }
        }
        return null;
    };
    PEHeader.prototype.readSection = function (i) {
        var size = this.sectionHeaders[i].sizeofRaw;
        var offset = this.sectionHeaders[i].pointertoRaw;
        var code = this.raw.subarray(offset, offset + size);
        return code;
    };
    PEHeader.prototype.readSectionDataByName = function (n) {
        for (var i = 0; i < this.sectionHeaders.length; i++) {
            if (this.sectionHeaders[i].name === n) {
                return this.readSection(i);
            }
        }
        return null;
    };

    PEHeader.prototype.load = function (m) {
        if (this.sectionHeaders.length === 0) {
            // Load the entire binary into memory (headers and all)
            var vaddr = this.imageBase;
            for (var i = 0; i < this.raw.byteLength; i++) {
                m.write_byte(vaddr | i, this.raw[i]);
            }
            return;
        }
        for (var i = 0; i < this.sectionHeaders.length; i++) {
            var raw = this.readSection(i);
            var vaddr = this.sectionHeaders[i].virtualAddress | this.imageBase;
            for (var j = 0; j < raw.length; j++) {
                m.write_byte(vaddr + j, raw[j]);
            }
        }
    };
    PEHeader.prototype.writeSectionDataByName = function (n, value) {
        for (var i = 0; i < this.sectionHeaders.length; i++) {
            if (this.sectionHeaders[i].name === n) {
                return this.writeSection(i, value);
            }
        }
        return null;
    };
    PEHeader.prototype.writeSection = function (i, v) {
        //var size = this.sectionHeaders[i].sizeofRaw;
        var offset = this.sectionHeaders[i].pointertoRaw;
        this.raw.set(v, offset);
    };

    /**
     * @constructor
     */
    function PEDirectoryEntry(ib) {
        this.rva = 0;
        this.vaddr = 0;
        this.offset = 0;
        this.size = 0;
    }

    PEDirectoryEntry.prototype.setvaddr = function (n, ib) {
        this.rva = n;
        this.vaddr = n | ib;
        //this.vaddr = n;
    };
    PEDirectoryEntry.prototype.setsize = function (n) {
        this.size = n;
    };

    /**
     * @constructor
     */
    function SectionHeader(n, a, b, c, d, e, f) {
        this.name = n;
        this.virtualSize = a;
        this.virtualAddress = b;
        this.sizeofRaw = c;
        this.pointertoRaw = d;
        this.ptrToRelocations = e;
        this.characteristics = f;
        //log("SECTIONHEADER", h(a), h(b), h(c), h(d), h(e), h(f));
    }

    if (!window["log"]) {
        window["log"] = function (a) {
            console.log(a);
        }
    }

    PEHeader.prototype["load"] = PEHeader.prototype.load;
    if (typeof window !== "undefined")
        window["pe_parse"] = pe_parse;
    else
        module["exports"]["pe_parse"] = pe_parse;
})();