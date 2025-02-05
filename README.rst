hwctl
=====
------------------------------------------------------------------
Local hardware-control setup using microcontrollers as peripherals
------------------------------------------------------------------

Microcontroller firmware and linux userspace scripts/services to control things
like LEDs, relays, buttons/switches and sensors connected to pins on those mcus
in my local setup.

Cheap hobby-microcontrollers like Arduinos_, ESP32_ and `RP2040 boards`_ are
easy to use as USB peripherals for normal PCs, to provide smart programmable
interface to a lot of simpler electrical hardware, electronics and common embedded
buses like I²C.

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
.. _ESP32: https://en.wikipedia.org/wiki/ESP32
.. _RP2040 boards:
  https://www.raspberrypi.com/documentation/microcontrollers/rp2040.html


`rp2040-usb-ppps`_
------------------
.. _rp2040-usb-ppps: rp2040-usb-ppps.py

RP2040 firmware-script used to control USB per-port-power-switching, but NOT via
actual built-in ppps protocol that some USB Hub devices support (and can be done
using sysfs on linux, or uhubctl_ tool), and instead via cheap solid-state-relays,
soldered to a simple USB Hub with push-button power controls on ports.

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

Implemented using mostly-stateless protocol sending single-byte commands over ttyACM
(usb tty) back-and-forth, so that there can be no "short read" buffering issues.

Script also implements listening to connected push-buttons, as configured in
HWCtlConf at the top, and sending one-byte events for those.

When using mpremote with RP2040s, ``mpremote run rp2040-usb-ppps.py``
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


`rp2040-neopixels`_
----------------------
.. _rp2040-neopixels: rp2040-neopixels.py

Script to display packed GIF pixel-art animation on a neopixel_ panel
like `Waveshare Pico-RGB-LED`_ 16x10 WS2812 LED matrix, looping it with
a random intervals a bunch of times. Intended to be used for flashy
visual reminders, from e.g. `nfc-sticker-actions`_ dispatcher.

`gif-frames-pack`_ tool below can be used to compress animated GIFs
into a couple lines of base64+zlib strings used in this script.

.. _neopixel: https://docs.micropython.org/en/latest/library/neopixel.html
.. _Waveshare Pico-RGB-LED: https://www.waveshare.com/wiki/Pico-RGB-LED


`hwctl`_
--------
.. _hwctl: hwctl.py

Linux userspace part of the control process - a daemon script to talk to
connected microcontrollers, receive button presses and send them commands,
proxied to/from whatever simple unixy IPC mechanisms, like files and FIFOs.

- Receiving button presses from MCU is handled via ``-F/--buttons-file`` option,
  to output those to a local file, which can be used as a queue, handled via some
  script woken-up by e.g. `systemd.path unit`_.

  For example, ``-F /tmp/btns-lights.log:mode=640:max-bytes=4_000:buttons=1,4-8,11``
  will dump specified buttons to an auto-rotated logfile at that path, with that mode.

  Something similar to ``tail -F /tmp/btns-lights.log`` can read lines from there.

- Command lines from a local FIFO (as in mkfifo_) can be read by using
  ``-f/--control-fifo`` option. Those are parsed and forwarded to connected microcontroller.

  Allows sending those from any shell script using e.g. ``echo usb3=on >hwctl.fifo``

  Currently parsed commands are (X=0-15): ``usbX=on``, ``usbX=off``, ``usbX=wdt``,
  which are encoded and sent to `rp2040-usb-ppps`_ script above.

- Can send commands to MCU, mapped to unix signals - via ``-s/--control-signal`` option.

  Same as with FIFO commands above, with specific signal bound to specific
  command via cli options, e.g. ``-s usr1=usb2=on -s usr2=usb2=off``

  Can be used via something like ``pkill -USR1 -F hwctl.pid``, allowing to
  set commands on hwctl invocation instead of in the script that triggers those.

Uses serial_asyncio module from `pyserial/pyserial-asyncio`_ for ttyACMx communication.

`Older version`_ used to poll /proc/self/mountinfo fd and do some "don't forget
to unmount" indication via LEDs connected to Arduino Uno board (running `hwctl.ino`_),
read/debounce physical buttons, as well as similar usb-control wdt logic as
rp2040-usb-ppps script.

.. _mkfifo: https://man.archlinux.org/man/mkfifo.1
.. _systemd.path unit: https://man.archlinux.org/man/systemd.path.5
.. _pyserial/pyserial-asyncio: https://github.com/pyserial/pyserial-asyncio
.. _Older version: https://github.com/mk-fg/hwctl/blob/0e60923/hwctl.py
.. _hwctl.ino: https://github.com/mk-fg/hwctl/blob/0e60923/hwctl.ino


`nfc-sticker-actions`_
----------------------
.. _nfc-sticker-actions: nfc-sticker-actions.py

Script to run configured commands from a simple `INI file`_ config
(like `nfc-sticker-actions.example.ini`_) when an NFC tag/sticker
(e.g. <$0.01 NTAG203/NTAG213 ISO14443 tags) with matching UID value
is pressed to a reader pad.

My use-case for this is sticking those cheap NTAGs on household chores/stuff
that's easy to forget about (like a tube of toothpaste to brush teeth before sleep),
and only snooze various notifications when that thing is tapped onto NFC-reader pad,
making it more difficult to forget about it, as disabling notification requires
holding damn thing in your hand already :)

Should be combined with any kind of notification or control/signaling scripts
(e.g. notify-send or timed-ble-beacon_ stuff) to actually do something notable
on desktop/network or in the physical world via ``[action: ...]`` sections
in the config file.

Data stored in NFC tag sectors isn't actually read by this script,
as it's enough to tell apart their unique-enough built-in UIDs for its purposes.

Optionally integrates with hwctl_ script above, to activate NFC pad via button,
so that it doesn't stay powered-on needlessly all the time (and start the script
itself via systemd.path_ unit when needed).
Cheap ACR122U pad I have draws ~300mA from USB, but likely also supports power
management commands to do same thing without any extra usb-ppps hardware.

Uses pyscard_ module for NFC reader communication, via `PCSC lite`_ on linux.

.. _INI file: https://en.wikipedia.org/wiki/INI_file
.. _nfc-sticker-actions.example.ini: nfc-sticker-actions.example.ini
.. _timed-ble-beacon:
  https://github.com/mk-fg/fgtk?tab=readme-ov-file#hdr-timed-ble-beacon
.. _systemd.path: https://man.archlinux.org/man/systemd.path.5
.. _pyscard: https://github.com/LudovicRousseau/pyscard
.. _PCSC lite: https://pcsclite.apdu.fr/


`gif-frames-pack`_
----------------------
.. _gif-frames-pack: gif-frames-pack.py

Helper script to efficiently pack GIF animation frames into an
easy-to-decode and relatively small sequential color arrays to
display via neopixel_ LED matrices (e.g. N-by-M rectangle of WS2812 LEDs),
via e.g. `rp2040-neopixels`_ script above.

For example, compresses complicated and messy 2,621-byte 16x8 49-frame
animated GIF format down to ~290 bytes, which are easy to embed into script
as base64 blob and iterate/loop over.

Uses `pillow/PIL module`_ to get pixels from GIF frames and ImageMagick_
command-line "magick" tool to get per-frame delays (not sure if PIL parses those).

.. _pillow/PIL module: https://pillow.readthedocs.io/
.. _ImageMagick: https://imagemagick.org/
