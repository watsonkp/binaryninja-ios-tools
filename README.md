# Objective-C and Swift Tools (v0.1)
Author: **Kevin Watson**

_A collection of helper functions for reversing Mach-O files compiled from Objective-C and/or Swift_

## Description:

This plugin is currently a partially completed mess. Needed to make the first commit at some point.

Can automatically parse class structures and rename function symbols to use their method names.
Using the Objective-C runtime implementation at https://opensource.apple.com/source/objc4/objc4-709/ as a reference.

Can demangle imported Swift symbols and comment their occurences in a function.
Using the Swift demangler implementation at https://github.com/apple/swift/ as a reference.



## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * release - 1.0.776


## Required Dependencies

The following dependencies are required for this plugin:

 * pip - enum34


## License

This plugin is released under a [MIT](LICENSE) license.


