#!/usr/bin/env python
import frida
import sys

# Load the javascript from our inject.js. That will be injected
# into the target!
inject_script = 'inject.js'
with open(inject_script, 'r') as f:
    js = f.read()

def on_message(msg, data):
    print("[-] recieved message from target:", msg)

def main():
    proc = 'a.out'
    device = frida.get_device('local')
    print(f'[+] Launching process {proc} suspended')
    pid = device.spawn(proc, stdio="pipe")
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
    device.input(pid, b'aaaa\n')

    # Stay alive. Until the detached_fn is run
    from sys import stdin
    stdin.read()

if __name__ == '__main__':
    main()
