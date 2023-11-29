hwctl
=====
------------------------------------------------------------------
Local hardware-control setup using microcontrollers as peripherals
------------------------------------------------------------------

Microcontroller firmware and linux userspace scripts/services to control things
like LEDs, relays, buttons/switches and sensors connected to pins on those mcus
in my local setup.

Cheap hobbyist microcontrollers like Arduinos_ and `RP2040 boards`_ are easy to
use as USB peripherals for normal PCs, to provide smart programmable interface
to a lot of simplier electrical hardware, electronics and common embedded buses
like I²C.

E.g. for stuff like switching power of things on-and-off with relays by sending
a command byte to /dev/ttyACM0, when it is needed/requested by whatever regular
OS - for example on click in some GUI, desktop keyboard shortcut, or when some
cronjob runs and needs external USB drive powered on.

Scripts here implement firmware and software side for some of my local setup,
and are probably not useful as-is to anyone else, as they have specific pins
connected to specific local hardware, so probably only useful for reference
and/or as a random example snippets.

It's very much in a "local hardware/firmware projects dump" or "dotfiles" category.

.. contents::
  :backlinks: none

Repository URLs:

- https://github.com/mk-fg/hwctl
- https://codeberg.org/mk-fg/hwctl
- https://fraggod.net/code/git/hwctl

.. _Arduinos: https://www.arduino.cc/
.. _RP2040 boards:
  https://www.raspberrypi.com/documentation/microcontrollers/rp2040.html


`rp2040-usb-ppps`_
------------------
.. _rp2040-usb-ppps: rp2040-usb-ppps.py

RP2040 firmware used to control USB per-port-power-switching, but NOT via actual
built-in ppps protocol that some USB Hub devices support (and can be done via
sysfs on linux, or uhubctl_ tool), and instead via cheap MOSFET solid-state-relays,
soldered to a cheap simple USB Hub with push-button power controls on ports.

Hubs with ppps have two deal-breaking downsides for me:

- They're impossible to find or identify - e.g. any model on uhubctl_ list of
  "known working" is either too old, can't be sourced from here, or is ridiculously
  expensive, while USB3 Hubs with port power dpdt switches are dirt-common and
  cost like $10.

  Chips in many hubs support ppps, but sometimes it toggles data lines and not
  VBUS, sometimes it only toggles one "fast charging" port, most times it
  doesn't do anything at all (control tracks not connected to anything), all this
  changes between minor hw revisions, and afaict not mentioned anywhere by vendors.

- PPPS in USB Hubs has default port power state as ON.

  So whenever you reboot the machine, dual-boot it into gaming-Windows or
  whatever, all the junk plugged into all ports powers-on all at once,
  which is dumb and bad - that's kinda the idea behind port power control to
  avoid this, and it takes its toll on devices (esp. spinning-rust ext-hdds).

  Also usually don't want non-main OS accessing stuff like Yubikeys at all
  (that lock themselves up after N access attempts), so power to those should
  always be default-disabled.
  In some cases, whole point of this per-port power control is to avoid
  seldom-used USB devices getting jerked around all the time, and ppps with
  default-on state is actually worse than simple always-on ports.

Controlling power via $1 SSRs soldered to buttons neatly fixes the issue -
nothing gets randomly powered-on, and when it does, code on the rp2040
controller can be smart enough to know when to shut down devices if whatever
using them stops sending it "this one is still in use" pings.

Implemented using mostly-stateless protocol sending single-byte commands over
ttyACM (usb tty) back-and-forth, so that there can be no "short read" buffering
issues.

When using mpremote with RP2040, ``mpremote run rp2040-usb-ppps.py``
won't connect its stdin to the script (at least current 2023 version of it),
so right way to actually run it seem to be uploading as ``main.py`` and do
``mpremote reset`` or something to that effect.

For deploying script as long-term firmware, pre-compiling it via
`mpy-cross tool`_ is probably a good idea::

  % mpy-cross -march=armv6m -O2 rp2040-usb-ppps.py -o usb_ppps.mpy
  % echo 'import usb_ppps; usb_ppps.run()' >loader.py
  % mpremote cp usb_ppps.mpy :
  % mpremote cp loader.py :main.py
  % mpremote reset

(mpy-cross binary used there is trivial to build - see `Arch PKGBUILD here`_)

Also wrote-up some extended thoughts on this subject in a
`"USB hub per-port power switching done right" blog post`_.

.. _uhubctl: https://github.com/mvp/uhubctl/
.. _mpy-cross tool:
  https://github.com/micropython/micropython/tree/master/mpy-cross
.. _Arch PKGBUILD here:
  https://github.com/mk-fg/archlinux-pkgbuilds/blob/master/mpy-cross/PKGBUILD
.. _"USB hub per-port power switching done right" blog post:
  https://blog.fraggod.net/2023/11/17/usb-hub-per-port-power-switching-done-right-with-a-couple-wires.html


`hwctl`_
--------
.. _hwctl: hwctl.py

Linux userspace part of the control process - a daemon script to talk to
connected microcontrollers and send them commands, received via whatever
simple unixy IPC mechanisms.

Currently itself controlled via signals (e.g. ``pkill -USR1 -F hwctl.pid``, see
``-p/--pid-file`` option) and any space/line-separated plaintext commands to a FIFO
pipe (``echo usb3=on >hwctl.fifo``, ``-f/--control-fifo`` option) from terminal or scripts.

Uses serial_asyncio module from `pyserial/pyserial-asyncio`_ for ttyACMx communication.

`Older version`_ used to poll /proc/self/mountinfo fd and do some "don't forget
to unmount" indication via LEDs connected to Arduino Uno board (running `hwctl.ino`_),
read/debounce physical buttons, as well as similar usb-control wdt logic as
rp2040-usb-ppps script.

.. _pyserial/pyserial-asyncio: https://github.com/pyserial/pyserial-asyncio
.. _Older version: https://github.com/mk-fg/hwctl/blob/0e60923/hwctl.py
.. _hwctl.ino: https://github.com/mk-fg/hwctl/blob/0e60923/hwctl.ino
