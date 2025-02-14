# MoxaNPort
This is a Wireshark dissector for two Moxa "NPort" protocols. The NPort devices are Ethernet/serial converters, the product range is very large and popular.

The dissector is written in Lua, allowing for an easy addition to any existing recent Wireshark installation. It is not dependent on the exact binary version of Wireshark, and can run on Windows and Ubuntu (and probably on MAC too). No need to install C++ development tools or the Wireshark source code!

# Installation
Copy the file 1:1 in the "plugins" folder (Help -> About Wireshark -> Folders -> Global Lua Plugins), that's it!
