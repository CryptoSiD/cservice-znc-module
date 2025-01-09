# cservice znc module
cservice ZNC module to log in to X on UnderNet. With 2FA/TOTP support.

Clone the repository, cd to cservice-znc-module folder and then run "znc-buildmod cservice.cpp"

Put the module cservice.so in ~/.znc/modules/

Load the module with "/znc loadmod service"

For the configuration, simply run /msg *cservice help

Enjoy!


NEW: The module now supports LoC (Login on Connect) https://www.undernet.org/loc/
You can also set your preferred usermode, either -x!, +x! or -!+x 
