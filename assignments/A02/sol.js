"use strict";

send({type: 'hello', hello_message: 'hello world'})

// Suggestions to help
var mem_allocations = {}; // Address => size. If you want
var first_allocation = true;

Interceptor.attach(Module.findExportByName(null, "malloc"), {
    /* Whenever malloc is called we need to save the size (first argument)
     * and the the return value. */
    onEnter: function(args) {
        this.allocsize = Number(args[0]); 
    },
    onLeave: function(address) {
        if (first_allocation) {
            first_allocation = false;
            var heap_range = Process.getRangeByAddress(address);
            send({type: 'heap_info', start: Number(heap_range.base),
                    end: Number(heap_range.base) + Number(heap_range.size)});
        }
        send({type: 'allocation', 'address': Number(address), 'size': this.allocsize})
        //console.log("STORE " + Number(address).toString(16) + " of size " + this.allocsize)
        mem_allocations[Number(address)] = this.allocsize
    }
})

Interceptor.attach(Module.findExportByName(null, "free"), {
    onEnter: function(args) {
        if (Number(args[0]) == 0) {
            return;
        }

        send({type: 'free', 'address': Number(args[0]), 'size': mem_allocations[Number(args[0])]});
    }
});
