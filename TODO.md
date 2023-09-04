Ports to create some day:
- busybox (build system is difficult to wrangle, don't know if I can do it)
- EasySIMBL: https://github.com/norio-nomura/EasySIMBL/
- OpenCFLite (opened ticket requesting it: https://trac.macports.org/ticket/38903)
- OpenPowerPlant: https://sourceforge.net/projects/open-powerplant/
- freexl (for gdal)
- PureDarwin (yes, the entire OS - make an image that can be run with qemu) (have stub with deps so far)
- stress (portfile submitted - https://trac.macports.org/ticket/38111) (should probably just patch the original source instead of using my own GitHub fork though)
- PackageMaker (the one from developer.apple.com - so `port pkg` can work more easily)
- "Packages" i.e. http://s.sudre.free.fr/Software/Packages/resources.html
- FlatCarbon-Headers (all of them, i.e. more than are in the CarbonHeaders port)
- other stuff from opensource.apple.com or from the Apple sample code that comes with Xcode.
- also other stuff that comes from macosforge
- libmp3hip (for MusicKit below) (in progress)
- GNS3: http://training.gns3.net/download/
- libfreenect: https://github.com/OpenKinect/libfreenect (submitted: https://trac.macports.org/ticket/39092)
- dssi (from Fink)

Stuff I've downloaded from SourceForge randomly in the past (check https://sourceforge.net/user/updates for full list):
- Open64
- ucc
- Prime Mover
- Daemonic
- MachOView(er)
- code-dump-ppc
- ExeToC Decompiler
- relipmoC
- kbuild - Linux Kernel Build (gcml)
- nwcc
- The Amsterdam Compiler Kit
- rcracki_mt
- wxHexEditor
- Hexplorer
- Qt#
- Qt Jambi
- qtcl
- Locomotive
- fetcav
- clamtk
- hspell-gui
- db2html
- MusicKit (in progress)

<!--
Copied and pasted from gnome-desktop-suite's comments hidden in its portfile:
#
# TODO
#
# The following modules are included in the current GNOME desktop
# environment specification but have not yet been ported to MacPorts
#
# brasero  (no support for darwin Mac OS X, requires Linux SG or BSD CAM)
# cheese   (requires Video4Linux or  V4L2)
# deskbar-applet
# ekiga (requires Video4Linux or  V4L2)
# evolution
# evolution-exchange
# evolution-mapi
# evolution-webcal
# gnome-bluetooth
# gnome-desktop-sharp
# gnome-disk-utility
# gnome-nettool
# gnome-packagekit
# gnome-power-manager
# gnome-screensaver
# gnome-system-tools
# gnome-user-share
# gok
# hampster-applet
# mousetweaks
# nautilus-sendto
# orca
# sound-juicer (depends on brasero)
# tomboy
# vinagre
#
# BROKEN PORTS
#
# The following ports are included in the current GNOME desktop
# environment specification and have been ported to MacPorts but
# are currently broken and/or need to be updated
#
# gnome-netstatus (builds but doesn't work -- tries to open /proc/net/dev)
# gnome-system-monitor (builds but segfaults on processes/resources -- probably due to lack of support for MacOSX in libgtop)
#
-->

Make sure every GNU package has a port:
http://www.gnu.org/software/software.html#allgnupkgs

AMD has opensource stuff; the only one they confirm to work on Mac though is Aparapi
I have been working on their CodeAnalyst though: https://github.com/cooljeanius/CodeAnalyst-3_4_18_0413-Public

Projects I've forked on GitHub but haven't made ports for yet (or updated their existing ports):
- libmspack (https://github.com/cooljeanius/libmspack)
- pict2pdf (https://github.com/cooljeanius/pict2pdf)
- bap (https://github.com/cooljeanius/bap)

Existing ports to fix/save:
- libnotify (in progress - https://trac.macports.org/ticket/39032)
- gnome-common (https://trac.macports.org/ticket/39037)
- thunderbird-x11 (https://trac.macports.org/ticket/39022)
- firefox-x11 (in progress - https://trac.macports.org/ticket/39023)
- dpkg (in progress - https://trac.macports.org/ticket/39018)
- apt (https://trac.macports.org/ticket/13425) 

