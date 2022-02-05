"use strict";

var active_mappings = {};

var heap_start = null;
var heap_end = null;

function initialize_monitor(address, size) {
    /* Set up heap monitor to detect use. This should only be called once
     * after we know how where the heap region of memory is */
    console.log("Monitoring from " + Number(address).toString(16) + "-" + (Number(address)+size).toString(16));
    heap_start = Number(address);
    heap_end = Number(address) + size;

    MemoryAccessMonitor.enable(
        {
            base: address,
            size: size,
        },
        {
            onAccess: function(details) {
                // This is what we do when there's an access to the heap
                console.log(
                    "operation: " + details.operation +
                    " from: " + details.from +
                    " address: " + details.address
                );
            }
        })
}

function initialize_stalker() {
    // "Stalk" the process and instrument every instruction
    // Why do we call this after the first malloc instead of at startup? Good question.
    // Because it doeesn't work when the process is suspended during initial creation.
    // Seems to be a frida bug? But it works now
    return;

    Stalker.follow(
    {
        events: {exec: true},

        transform(iterator){
          let instruction = iterator.next()
          do {
              for (const idx in instruction.operands) {
                  var insn_details = instruction.operands[idx];
                  if (insn_details["type"] != "mem") {
                      continue;
                  }

                  var addr = instruction['address']
                  var reg = insn_details["value"]["base"]
                  var disp = insn_details["value"]["disp"]
                  var mod = Process.findModuleByAddress(addr);

                  if (mod == undefined) {
                      var label = "unkown";
                  }else{
                      var label = `${mod['name']} + 0x${(addr - Number(mod['base'])).toString(16)}`
                      if (mod['name'] == 'a.out') {
                          console.log(`${addr.toString(16)}: ${instruction}`);
                      }
                  }

                  iterator.putCallout(function match(context) {
                      var memloc = Number(context[reg]) + Number(disp);
                      if (heap_start != null && memloc >= heap_start && memloc < heap_end) {
                          console.log(`${label}: accesses 0x${memloc.toString(16)} ${memloc-heap_start} bytes into the heap`);
                      }
                  });

              }
            iterator.keep()
          } while ((instruction = iterator.next()) !== null)
        },
    });
}

var first = true;
Interceptor.attach(Module.findExportByName(null, "malloc"), {
    /* Whenever malloc is called we need to save the size (first argument)
     * and the the return value. */
    onEnter: function(args) {
        // Entering malloc
        this.allocsize = Number(args[0]); // Save address (as number) so we can read in OnLeave
    },
    onLeave: function(address) {
        // Returning from malloc
        if (first) {
            first = false;

            var heap_range = Process.getRangeByAddress(address);
            console.log("First heap allocation: " + JSON.stringify(heap_range));
            initialize_stalker();
            initialize_monitor(heap_range.base, heap_range.size);
        }else {
            // The heap shouldn't move around, this will always be the same
            //console.log("Subsequent heap allocation: " + JSON.stringify(heap_range));
        }

        active_mappings[Number(address)] = this.allocsize;
        console.log(`Allocate ${this.allocsize} bytes at 0x${address.toString(16)}`);
    }
})

Interceptor.attach(Module.findExportByName(null, "free"), {
    onEnter: function(args) {
        var addr = Number(args[0]);
        console.log("Just freed 0x" + addr.toString(16) + " of size " + active_mappings[addr]);
        delete active_mappings[addr];
    }
});
