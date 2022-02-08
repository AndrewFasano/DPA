Assignment 02: Heap Analyzer + Minecraft Returns
=====

By popular demand, the original version of this assignment has been simplified and we're going to have a second part focused on Minecraft.

# Part 1: Frida Heap Analyzer

Using Frida we are going to examine malloc and free calls and track allocations. If you're not familiar with these, it's definitely
worth reading the man page or some background

### Who cares about the heap?
Use after free or UAF is a common vulnerability type where an object is allocated on the heap, a reference to it
is stored, and then the object is unallocated, but the reference to it is left behind. If the 
code then uses that reference, it will read random memory. In many situations the memory is used
as a function pointer which could cause execution to jump to somewhere it shouldn't. Even worse,
users often have some control of memory allocations and, if they have the program allocate a buffer
of the same size, they can place arbitrary data into memory where the object originally was.
For example, consider the following buggy code:

```
char* data1 = (char*)malloc(64);
data1[0] = 'h';
data1[1] = 'i';
data1[2] = 0;

free(data1);

char* data2 = (int*)malloc(64);
fgetc(data2, 64, stdin);

printf(data1); // This could now contain the attacker-provided data2.
```

We're not going to be building a UAF detector today (Frida isn't really the best tool for it), but we're
instead going to hook malloc and free and just log some information.

## Tasks

Examine the provided, `run.py`, `inject.js` and `prog.c`. Your goal is to modify the `inject.js` code
such that it reports information back to Python such that the `on_message` function in `run.py` gets the various types
of messages it supports: `heap_info`, `allocation` and `free`.

`allocation` and `free` should both be given a pointer and a size. You may want to convert the addresses you get
from Frida into regular numbers using the `Number()` function. 

`heap_info` is a little more tricky, you'll want to provide this info before recording the very first allocation. Using Frida's
APIs, you're going to take the first pointer returned from malloc and convert it into an address range for the heap.

You shouldn't need to make any modifications to files other than `inject.js`.


# Part 2: Minecraft returns

We're going to do some simple Frida-based analysis and modification of a Minecraft server.

##  Setup

To begin, pull the [containers repo](https://github.com/AndrewFasano/DPA-containers) and build the `Dockerfile_mc` in the frida directory which will set you up with Frida built from source, a Java JDK with debug symbols that actually works with Frida and a minecraft server:
```
user@host: path/to/DPA/Containers $ docker built -t frida_minecraft -f frida/Dockerfile_mc frida/
```

Launch the container with port 25565 bridged to your host:
```
docker run --rm -it -v$(pwd):/host -p 25565:25565 frida_minecraft
```

Then launch a second bash shell in the container (see L03 slides for more details).

In your first shell, launch the Minecraft server with
```
 /java/openjdk-11.0.13_8/bin/java -Xmx1024M -Xms1024M -jar /java/minecraftserver.1.3.1.jar nogui
```

It will print an error about how you need to agree to the eula - do what it says (edit the config file and change false to true).


Now launch the server again, you should see messages like `2022-02-08 21:32:17 [INFO] Preparing spawn area: 12%` and
eventually `2022-02-08 21:32:26 [INFO] Done (11.846s)! For help, type "help" or "?"`. 

During or after setup, in your second shell in the guest, run the command `frida java` and check that running `Java.available` returns `true`.

## Analysis

Minecraft has a bunch of obfuscated function names like `aa` and `ab` which don't convey much meaning to us.
Instead of trying to understand those, we're going to analyze and modify the Java string objects as they're created, these use standard names that Minecraft can't hide.
You should build a snippet of JavaScript which, when entered into the Frida console will prevent a user named `frida` from being banned from the server.
You might do this by hooking String objects as they're created and, if you see a message to ban that user, modifying it.
You could take a look at [this article](https://www.flowerbrackets.com/string-constructors-in-java/) to learn more about how Java string constructors work.
The solution for this assignment involves hooking one of the functions listed there.

In my testing, I found that frida would hang or crash the server every so often, but it's quick to restart the server and frida when that happens (ctrl-z + `kill -9 %1` worked well for me).

This is a minimal modification and not too exciting, but Minecraft is tricky to analyze due to its size and obfuscation.
If you can do anything else interesting, you're welcome to do that instead of the ban prevention.
To be a bit more precise about what I'd consider interesting here's some guidelines: at least 10 lines of code, modify game state in some way such
as changing the type of blocks that are in a map or the location of users, passively record when some action occurs with details about it.
Be sure the state you're modifying or recording isn't simply available in the various config files that are created on disk.

If you want to connect to the server, you can configure your Minecraft launcher to download a client of the same version (1.3.1) under the `installations` tab.
If you have issues with a specific client version, you can try upgrading your server to another similarly old version.
I was able to get frida's `Java.available` to return `true` on v 1.14, but it seemed to be more obfuscated.

To get you started, here are a few snippets of code which uses Java to interact with the Minecraft server. Note that you can write scripts into a file and run them
with `frida -l yourfile.js java`. If you add `-o log.txt` the output will be logged to `log.txt`.


For every known class, enumerate available methods and print type information (lots of output)
```
function enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();
    hook.$dispose;
    return ownMethods;
};

Java.perform(function(){
	Java.enumerateLoadedClasses({"onMatch":
		function(c){
			console.log(c);
			try {
                var a = enumMethods(c);
                a.forEach(function(s) {
                     console.log("\t" + s);
                });
            } catch {
                console.log("error");
            }
        }
    })
});
```

Overload the string comparison method and log when unequal strings are compared:
```
Java.perform(function() {
    var str = Java.use('java.lang.String');
    str.equals.overload('java.lang.Object').implementation = function(obj) {
        var response = str.equals.overload('java.lang.Object').call(this, obj);
        if (obj && obj.toString().length > 3 && !response) {
			console.log(str.toString.call(this) + " != " + obj.toString())
        }
        return response;
    }
});
```
