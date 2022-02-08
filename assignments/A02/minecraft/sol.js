var strbld = Java.use("java.lang.StringBuilder");

strbld.toString.overload().implementation = function(){
	var ret = strbld.toString.overload().call(this);
	if (ret.includes("frida")) {
		ret = ret.replace("frida", "aaaaa")
		console.log("\nCHANGE")
	}
	return ret;
}
