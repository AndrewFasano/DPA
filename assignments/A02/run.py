#!/usr/bin/env python
import frida
import sys

# Load the javascript from our inject.js. That will be injected
# into the target!
inject_script = 'inject.js'
with open(inject_script, 'r') as f:
    js = f.read()

heap_start = None
heap_end = None

def on_message(msg, data):
    global heap_start, heap_end

    if not 'payload' in msg:
        print("[-] recieved message from target:", msg)
        return
    elif 'type' in msg['payload']:
        msg_type = msg['payload']['type']
        if msg_type == 'hello':
            # Optional
            print("Got hello message:", msg['payload']['hello_message'])
        elif msg_type == 'heap_info':
            assert(heap_start is None), "Error: duplicate heap_info message"
            heap_start = msg['payload']['start']
            heap_end = msg['payload']['end']

        elif msg_type == 'allocation':
            address = msg['payload']['address']
            size = msg['payload']['size']
            assert (heap_start is not None), "Error: Allocation before heap_info"
            assert(address > heap_start)
            assert((address+size) < heap_end)
            print(f"Allocate 0x{address:x} of size {size}. This buffer is {address-heap_start:x} bytes into heap")

        elif msg_type == 'free':
            address = msg['payload']['address']
            size = msg['payload']['size']
            print(f"Free buffer at {address:x} of size {size}")
    else:
        print(f"Error: messgae with unspecified type: {repr(msg)}")

def main():
    if len(sys.argv) < 2:
        raise ValueError(f"USAGE {sys.argv[0]} [program_to_trace: e.g., /bin/ls or ./a.out]")

    proc = sys.argv[1]

    device = frida.get_device('local')
    print(f'[+] Launching process {proc} suspended')
    pid = device.spawn(proc, stdio="pipe",)
    session = device.attach(pid)

    print(f'[+] Process created. Injecting {inject_script}...')
    script = session.create_script(js)

    script.on('message', on_message)
    script.load()

    def output_fn(pid, fd, data):
        print(f"[+] Process {pid} outputs {repr(data)}")
    device.on("output", output_fn)

    def detached_fn(reason, *args):
        print(f"[-] Detaching with reason={repr(reason)}. Ending analysis")
        sys.exit(1)
    session.on("detached", detached_fn)

    print(f'[+] Resuming {proc}.')
    device.resume(pid)

    # Provide some input
    #device.input(pid, b'aaaa\n')

    # Stay alive. Until the detached_fn is run
    from sys import stdin
    stdin.read()

if __name__ == '__main__':
    main()
