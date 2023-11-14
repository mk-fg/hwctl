hwctl
=====
------------------------------------------------------------------
Local hardware-control setup using microcontrollers as peripherals
------------------------------------------------------------------

Microcontroller firmware and linux userspace scripts/services to control things
like relays and sensors connected to pins on those mcus in my local setup.

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
