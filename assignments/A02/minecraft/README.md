Server from:
    https://www.minecraft.net/en-us/download/server - tested v1.18.1
    Launch, edit config to set eula=true, then launch again

Newer OpenJDK with debug symbols in binaries (different from apt's -dbg package)
    https://adoptium.net/releases.html?variant=openjdk17&jvmVariant=hotspot

    V17 can launch latest minecraft but has frida error:
        Java API only partially available; please file a bug. Missing: _ZN6Method24restore_unshareable_infoEP6Thread, _ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_
        These are both available in frida-java-bridge since 2 years ago https://github.com/frida/frida-java-bridge/commit/6b56e2ce2c88c314988243867c6e5a272028f1ad

Frida from source:
    Hoping to get the JDK support which looks to exist in git despite the error using frida from pip

    ```
    git clone --recurse-submodules https://github.com/frida/frida.git
    make python-linux-x86_64 PYTHON=$(which python3) # Makefile needs python3.8+ path
    ```

    Failed: frida-core/meson.build:1:0: ERROR: Unknown compiler "/frida/build/frida-linux-x86_64-valac"

    Rebuildling interactively, starting with make target `core-linux-x86_64`, then `make python-linux-x86_64 PYTHON=$(which python3)` worked!


Python bindings:
    `export FRIDA_EXTENSION=/frida/build/frida-linux-x86_64/lib/python3.8/site-packages/_frida.so`
    `export FRIDA_VERSION=$(git describe --tags)`
    cd /frida/frida-python
    python3.8 setup.py install

Python frida-cli:
    cd /frida/frida-tools && make
    python3.8 setup.py install


Container now has frida! Trying out minecraft annnd...

```
%resume
[Local::java]-> Java.available
Error: Java API only partially available; please file a bug. Missing: _ZN6Method24restore_unshareable_infoEP6Thread, _ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_
at P (frida/node_modules/frida-java-bridge/lib/jvm.js:143)
at C (frida/node_modules/frida-java-bridge/lib/jvm.js:12)
at _tryInitialize (frida/node_modules/frida-java-bridge/index.js:17)
at y (frida/node_modules/frida-java-bridge/index.js:9)
at <anonymous> (frida/node_modules/frida-java-bridge/index.js:320)
```

Hacking up source of jvm.js
then touch `frida-gum/bindings/gumjs/runtime/java.js` and `make tools-linux-x86_64`


Ignoring all that.
    Server 1.14 from https://mcversions.net/download/1.14
    OpenJDK `11.0.13_8` from https://github.com/AdoptOpenJDK/openjdk11-upstream-binaries/releases/tag/jdk-11.0.13%2B8
    `Java.avilable = True`!

    
    Start container with `docker run --rm -it -v$(pwd)/mc:/mc -p 25565 frida_mc`
    /java/openjdk-11.0.13_8/bin/java -Xmx1024M -Xms1024M -jar /java/minecraftserver.1.14.jar nogui

Frida-based analyses
    // Log all known functions
    Java.perform(function(){Java.enumerateLoadedClasses({"onMatch":function(c){console.log(c);}});});


    Resources: https://gist.github.com/daniellimws/50b1112cf6408290d9da03398a7aac7f
    and https://github.com/iddoeldor/frida-snippets


from: https://awakened1712.github.io/hacking/hacking-frida/. Class inspector
```
const Class = Java.use("java.lang.Class");
function inspectObject(obj) {
    const obj_class = Java.cast(obj.getClass(), Class);
    const fields = obj_class.getDeclaredFields();
    const methods = obj_class.getMethods();
    console.log("Inspecting " + obj.getClass().toString());
    console.log("\tFields:");
    for (var i in fields)
        console.log("\t\t" + fields[i].toString());
    console.log("\tMethods:");
    for (var i in methods)
        console.log("\t\t" + methods[i].toString());
}
```

com.mojang.authlib.GameProfile
com.mojang.datafixers.kinds.IdF$Instance
com.mojang.datafixers.kinds.Applicative
com.mojang.datafixers.kinds.Functor
com.mojang.datafixers.kinds.Kind1
com.mojang.datafixers.util.Unit
com.mojang.brigadier.arguments.StringArgumentType$StringType
com.mojang.datafixers.FunctionType$Instance
com.mojang.datafixers.optics.profunctors.MonoidProfunctor
com.mojang.datafixers.optics.profunctors.Mapping
com.mojang.datafixers.optics.profunctors.TraversalP
com.mojang.datafixers.optics.profunctors.AffineP
com.mojang.datafixers.optics.profunctors.Cartesian
com.mojang.datafixers.optics.profunctors.Cocartesian
com.mojang.datafixers.optics.profunctors.Monoidal
com.mojang.datafixers.optics.profunctors.Profunctor
com.mojang.datafixers.kinds.Kind2
com.mojang.datafixers.kinds.App
com.mojang.datafixers.TypeRewriteRule$Nop
com.mojang.datafixers.TypeRewriteRule
com.mojang.datafixers.Dynamic
com.mojang.datafixers.DynamicLike
com.mojang.datafixers.functions.PointFreeRule$CompAssocRight
com.mojang.datafixers.functions.PointFreeRule$SortProj
com.mojang.datafixers.functions.PointFreeRule$SortInj
com.mojang.datafixers.functions.PointFreeRule$CompAssocLeft
com.mojang.datafixers.functions.PointFreeRule$LensCompFunc
com.mojang.datafixers.functions.PointFreeRule$AppNest
com.mojang.datafixers.functions.PointFreeRule$LensComp
com.mojang.datafixers.functions.PointFreeRule$LensAppId
com.mojang.datafixers.functions.PointFreeRule$CataFuseDifferent
com.mojang.datafixers.functions.PointFreeRule$CataFuseSame
com.mojang.datafixers.functions.PointFreeRule$CompRewrite
com.mojang.datafixers.functions.PointFreeRule
com.mojang.datafixers.types.templates.TypeTemplate


Switched back to v1.12 because it looks less obfscurated


function enumMethods(targetClass) { var hook = Java.use(targetClass); var ownMethods = hook.class.getDeclaredMethods(); hook.$dispose; return ownMethods; }

Java.perform(function() {
        // enumerate all methods in a class
        var a = enumMethods("net.minecraft.server.MinecraftServer")
        a.forEach(function(s) { 
                console.log(s); 
        });
});


// com.mojang.authlib.GameProfile.getName(
Java.perform(function(){
        a=Java.use("net.minecraft.server.MinecraftServer");
        var b=a.$new();
        console.log(b.getServerModName());
        })

String logging (works) via https://codeshare.frida.re/@ninjadiary/frinja----java-io/
```
var strbld = Java.use("java.lang.StringBuilder");

strbld.toString.overload().implementation = function(){
	var ret = strbld.toString.overload().call(this);

	if (ret != 'true')
		console.log("StringBuilder.toString(): " + ret);
	if (ret.includes("gameMode.survival")) {
		ret = ret.replace("gameMode.survival", "gameMode.creative")
		console.log("\nCHANGE")
	}
	return ret;
}

strbld.toString.overload().implementation = function(){
	var ret = strbld.toString.overload().call(this);
	if (ret != "true")
		console.log("StringBuilder.toString(): " + ret);
	return ret;
}
```

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

This is working on v1.3.1, but Frida is causing problems on 1.14

Exercise: Make it impossible to ban an player named frida by messing with string constructors

All everything:

```
function enumMethods(targetClass) { var hook = Java.use(targetClass); var ownMethods = hook.class.getDeclaredMethods(); hook.$dispose; return ownMethods; };
Java.perform(function(){
	Java.enumerateLoadedClasses({"onMatch":
		function(c){
			console.log(c);
			try {
                var a = enumMethods(c);
                a.forEach(function(s) {
                     console.log(c + "->" + s);
                });
            } catch {
                console.log("error");
            }
        }
    })
});
```

Min:
```
function enumMethods(targetClass) { var hook = Java.use(targetClass); var ownMethods = hook.class.getDeclaredMethods(); hook.$dispose; return ownMethods; }; Java.perform(function(){ Java.enumerateLoadedClasses({"onMatch": function(c){ console.log(c); try { var a = enumMethods(c); a.forEach(function(s) { console.log(c + "->" + s); }); } catch { console.log("error"); } } }) });
```


Assignment:

We're going to do some simple Frida-based analysis and modification of a Minecraft server.

##  Setup

To begin, pull the [containers repo](https://github.com/AndrewFasano/DPA-containers) and build the Dockerfile_mc in the frida directory which will set you up with Frida built from source, a Java JDK with debug symbols that actually works with Frida and a minecraft server:
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
