LAB02: Minecraft Tracing
====

Today we will be using Frida to do some DBI on the game Minecraft! This is as
real-world as these labs can get: you're going to have to set up something
non-trivial and then, once your system is set up, your dynamic program analysis
skills are going to make your goals pretty easy:

Goals:
1) Using DBI of Minecraft, teleport your player to a new location
2) Use a DBI script, log Minecraft chat messages to a text file


## Part 1: System setup
For today's exercises, you're going to need
to run Minecraft under with OpenJDK and have access to the GUI created by Minecraft.

If your host machine is OSX or Linux, you might want to do this outside the container. If you're on windows, you'll need WSL or a container
because Frida doesn't support Java introspection on windows.

Roughly, you'll want to do the following. Feel free to ask for as much help as you want from the instructor or your peers.

Decide where you'll run this lab: docker or on your host machine.
We will be running a graphical application so I'd recommend against docker if possible. On windows WSL should work, on OSX and Linux you should be able to just set it up on your host.

If you go with docker, you'll need to expose a GUI on your host. On Linux that would require you to run with ` -v /tmp/.X11-unix:/tmp/.X11-unix` and possibly to set the 
environment variable `DISPLAY=:0` inside your container.

### Windows specific setup
Install VcXsrv so that you can run graphical apps from WSL (description and link at https://askubuntu.com/a/993331.)
Open windows powershell as admin, run
 ```
 New-NetFirewallRule -DisplayName "WSL" -Direction Inbound  -InterfaceAlias "vEthernet (WSL)"  -Action Allow
 ```
Launch VcXsrv, on the third page add `-ac` as an additional option in the text box.
In WSL run
```
export DISPLAY=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}'):0
```
You should now be able to run graphical apps (you can try `xeyes` for example)

### General setup:

Make sure your environment has Python3, and install Frida with pip: `pip install frida-tools frida`.

Next you need to install OpenJDK for your host machine.
This is a Java Virtul Machine (JVM) which runs Java applications like Minecraft.
Unlike the standard one, this one has debugging symbols which Frida can use to tell you what's going on.
You can install it from your package manager (`openjdk-11-jre`) or from https://www.microsoft.com/openjdk.

Install the Minecraft Java Edition free trial (be sure to select the right OS)
https://www.minecraft.net/en-us/free-trial
You will need to create an account.

You may need to install the package `libsecret-1.0` from your package manager if you get errors trying to start the launcher

Run the minecraft launcher. It will open a launcher window called "Minecraft Launcher" where you
can configure How the game is actually launched. You need to reconfigure it to use the OpenJDK you installed instead of the regular one it includes.

Under the `Installations` tab, mouse-over `Latest release` and click the three dots, then edit.
Under `more options` select `java executable` and provide the path to java in your openjdk directory. This should be something like`/usr/lib/jvm/java-11-openjdk-amd64/bin/java.exe`.


Go back to th3e `Play` tab and launch the java edition.
After a minute, it should take you to a window that says `singleplayer` and `multiplayer` in gray boxes. At this point, our target process is running and hopefully set up for us to analyze it!

Attach to Minecraft from Frida: Use frida-ps to find the name of the java process (mine was javaw.exe) and then attach by running Frida with that as an argument.

Make sure you've set everything up and that Frida can introspect by running
```
Process.enumerateModules()[0];
Java.available
```

The first command should print the path to your hotspot JDK and the second should print true. Now you're good to go


## Part 2: Use Frida!
Start a game in minecraft, pressing F3 shows some debug info such as your coordinates. Use Frida to search memory for these values and try changing them!

Send a chat message in the game, agian use Frida to find it. Try tracking a function which will be called with this as an argument using Frida's tracer.
