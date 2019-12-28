// Flat 4 GB address space implementation for JS.
(function () {
    /** @constructor */
    function Memory() {
        this.pages = [];
        this.memorySize = 0x100000000;
        this.actualSize = 0;

        this.nextFreeMemoryAvailable = 0;
    }

    Memory.prototype.write_byte = function (address, data) {
        var page = address >>> 12;
        var offset = address & 0xFFF;
        if (!this.pages[page]) {
            this.pages[page] = new Uint8Array(4096);
            this.actualSize += 4096;
        }
        this.pages[page][offset] = data;
    };
    Memory.prototype.write_word = function (address, data) {
        var page = address >>> 12;
        var offset = address & 0xFFF;
        if (!this.pages[page]) {
            this.pages[page] = new Uint8Array(4096);
            this.actualSize += 4096;
        }
        if (offset !== 0xFFF) {
            this.pages[page][offset] = data & 0xFF;
            this.pages[page][offset + 1] = data >> 8 & 0xFF;
        } else {
            this.pages[page][0xFFF] = data & 0xFF;
            this.write_byte(address + 1, data >> 8);
        }
    };
    Memory.prototype.write_dword = function (address, data) {
        var page = address >>> 12;
        var offset = address & 0xFFF;
        data |= 0;
        if (!this.pages[page]) {
            this.pages[page] = new Uint8Array(4096);
            this.actualSize += 4096;
        }
        if (offset < 0xFFC) {
            this.pages[page][offset] = data & 0xFF;
            this.pages[page][offset + 1] = data >> 8 & 0xFF;
            this.pages[page][offset + 2] = data >> 16 & 0xFF;
            this.pages[page][offset + 3] = data >> 24 & 0xFF;
        } else {
            this.write_word(address, data);
            this.write_word(address + 2, data >> 16);
        }
    };
    Memory.prototype.print_memory_usage = function () {
        console.info(this.actualSize);
        console.info("Memory usage: " + (this.actualSize / 1024).toString(10) + " KB, " + (this.actualSize === 0 ? 0 : (this.actualSize / 0x100000000) * 100).toFixed(5) + "% of memory used");
    };
    Memory.prototype.read_byte = function (address) {
        var page = address >>> 12;
        var offset = address & 0xFFF;
        if (!this.pages[page]) {
            return 0;
        }
        return this.pages[page][offset];
    };
    Memory.prototype.read_word = function (address) {
        var page = address >>> 12;
        var offset = address & 0xFFF;
        if (offset === 0xFFF) {
            return this.read_byte(address) | this.read_byte(address + 1) << 8;
        }
        if (!this.pages[page]) {
            return 0;
        }
        return this.pages[page][offset] | this.pages[page][offset + 1] << 8;
    };
    Memory.prototype.read_dword = function (address) {
        var page = address >>> 12;
        var offset = address & 0xFFF;
        if (offset > 0xFFB) {
            return this.read_word(address) | this.read_word(address + 2) << 16;
        }
        if (!this.pages[page]) {
            return 0;
        }
        return this.pages[page][offset] | this.pages[page][offset + 1] << 8 | this.pages[page][offset + 2] << 16 | this.pages[page][offset + 3] << 24;
    };
    Memory.prototype.read_string = function (address, length) {
        var len_ = length, offs = 0;
        var str = "";
        while (length--) {
            str += String.fromCharCode(this.read_byte(address + (offs++)));
        }
        return str;
    };
    Memory.prototype.read_zero_terminated_string = function (address) {
        var offs = 0;
        var str = "";
        while (this.read_byte(address + (offs))) {
            str += String.fromCharCode(this.read_byte(address + (offs++)));
        }
        return str;
    };
    Memory.prototype.read_zero_terminated_utf16_string = function (address) {
        var offs = 0;
        var str = "";
        while (this.read_word(address + (offs))) {
            str += String.fromCharCode(this.read_word(address + (offs)));
            offs += 2;
        }
        return str;
    };
    Memory.prototype.read_array = function (address, len) {
        var offs = 0;
        var arr = new Uint8Array(len);
        while (len--) {
            arr[offs] = this.read_byte(address + (offs++));
        }
        return arr;
    };
    Memory.prototype.write_array = function (address, arr) {
        var offs = 0;
        var len = arr.byteLength;
        while (len--) {
            arr[offs] = this.write_byte(address + (offs), arr[offs++]);
        }
        return arr;
    };
    Memory.prototype.save_state = function () {
        var x = [];
        for (var i = 0; i < this.pages.length; i++) {
            var page = this.pages[i];
            if (!page) {
                x.push(0x01);
            } else {
                x.push(0x42);
                for (var j = 0; j < 4096; j++) {
                    x.push(page[j]);
                }
            }
        }
        return new Uint8Array(x);
    };
    Memory.prototype.restore_state = function (input) {
        var new_pages = [];
        var page_no = 0;
        for (var i = 0; i < input.length; i++ , page_no++) {
            if (input[page_no] === 0x69) {
                continue;
            } else {
                i++;
                new_pages[page_no] = new Uint8Array(4096);
                for (var j = 0; j < 4096; j++) {
                    new_pages[page_no][j] = input[i++];
                }
                i--;
            }
        }
        this.pages = new_pages;
    };
    Memory.prototype.write_buffer = function (b, offset) {
        for (var i = 0; i < b.length; i++) {
            this.write_byte(offset + i, b[i] & 0xFF);
        }
    };
    Memory.prototype.read_string = function (address, length) {
        var len_ = length, offs = 0;
        var str = "";
        while (length--) {
            str += String.fromCharCode(this.read_byte(address + (offs++)));
        }
        return str;
    };
    Memory.prototype.read_zero_terminated_string = function (address) {
        var offs = 0;
        var str = "";
        while (this.read_byte(address + (offs))) {
            str += String.fromCharCode(this.read_byte(address + (offs++)));
        }
        return str;
    };
    Memory.prototype.write_string = function (address, data) {
        var len_ = data.length, offs = 0;
        while (len_--) {
            this.write_byte(address + (offs), data[offs++]);
        }
    };

    /**
     * Frees memory 
     * @param {number} address
     * @param {number} amount
     * 
     * @return {boolean} True if one or more pages have been freed.
     */
    Memory.prototype.free = function (address, amount) {
        //  1) If it's the length of a page (or a multiple of it), then remove the page,
        //    freeing 4k of memory
        //  2) If it's the length of a page and spills over a bit, then check if the
        //    partial page has anything on it besides the freed region. If they're zeros,
        //    then delete that page.
        //  3) If it's a partial page, then check if the regions around it have any data.
        //    If they're zeros, then delete that page.
        // Situation 1: Check if base address is 0 and we have a multiple of 4096 (% 4096
        // = & 0xFFF)
        if ((address & 0xFFF) === 0 && (amount & 0xFFF) === 0) {
            var pages_to_free = amount >>> 12;
            var base_page = address >>> 12;
            var end = pages_to_free + base_page;
            for (var i = base_page; i < end; i++) {
                delete this.pages[i];
            }
            return true;
        }
        // Situation 2: Check if base address is 0 and we go more than a page.
        if ((address & 0xFFF) === 0 && (amount > 0x1000)) {
            var pages_to_free = amount >>> 12;
            var base_page = address >>> 12;
            var end = pages_to_free + base_page;
            for (var i = base_page; i < end; i++) {
                delete this.pages[i];
            }
            // "end" is our partial page address.
            var p = this.pages[end];
            if (!p) {
                // Page wasn't allocacated anyways.
                return true;
            }
            var offset = amount & 0xFFF;
            for (var i = offset; i < 0x1000; i++) {
                if (p[i] !== 0) {
                    // Bail out if we were overoptimistic
                    return false;
                }
            }
            delete this.pages[end];
            return true;
        }
        // Situation 3: Partial page removal.
        var offset = amount & 0xFFF;
        var page = this.pages[address >>> 12];
        if (!page) {
            return true;
        }
        for (var i = offset; i < 0x1000; i++) {
            if (p[i] !== 0) {
                return false;
            }
        }
        delete this.pages[address >>> 12];
    };

    // Closure Compiler
    Memory.prototype["read_byte"] = Memory.prototype.read_byte;
    Memory.prototype["read_word"] = Memory.prototype.read_word;
    Memory.prototype["read_dword"] = Memory.prototype.read_dword;
    Memory.prototype["write_byte"] = Memory.prototype.write_byte;
    Memory.prototype["write_word"] = Memory.prototype.write_word;
    Memory.prototype["write_dword"] = Memory.prototype.write_dword;
    if (typeof window !== "undefined")
        window["Memory"] = Memory;
    else
        module["exports"]["Memory"] = Memory;
})();