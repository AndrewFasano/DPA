"use strict";

var active_mappings = {};
var free_mappings = {};

function watch_for(addr) {
    console.log("Monitoring just freed region: " + addr.toString(16));
    console.log("Size was:" + free_mappings[addr]);

    MemoryAccessMonitor.enable(
        {
            base: addr,
            size: 0x400, 
        },
        {
            onAccess: function(details) {
                console.log(
                    "operation: " + details.operation + 
                    " from: " + details.from +
                    " address: " + details.address
                );
            }
        })
}


Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter: function(args) {
        this.allocsize = Number(args[0]) ; // Save address (as number) for onLeave to use
    },
    onLeave: function(address) {
        active_mappings[address] = this.allocsize;
        console.log("Allocate buffer of size " + this.allocsize + " at 0x" + address.toString(16));
    }
})

Interceptor.attach(Module.findExportByName(null, "free"), {
    onEnter: function(args) {
        var addr = args[0];
        console.log("free buffer at 0x" + addr.toString(16));

        if (addr in active_mappings) {
            free_mappings[addr] = active_mappings[addr];
            console.log("just freed buffer at " + addr.toString(16) + " size was " + active_mappings[addr]);
            watch_for(addr);
        }else{
            console.log("Unknown buffer");
        }
    }
});
