# hwctl

Local hardware-control setup using microcontrollers as peripherals.

Microcontroller firmware and linux userspace scripts/services to control things
like LEDs, relays, buttons/switches and sensors connected to pins on those mcus
in my local setup.

Cheap hobby-microcontrollers like [Arduinos], [ESP32] and [RP2040 boards] are
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

[Arduinos]: https://www.arduino.cc/
[ESP32]: https://en.wikipedia.org/wiki/ESP32
[RP2040 boards]:
  https://www.raspberrypi.com/documentation/microcontrollers/rp2040.html

Contents - different scripts in this repo:

- [mpy-usb-ppps]
- [mpy-neopixels]
- [hwctl]
- [nfc-sticker-actions]
- [gif-frames-pack]

[mpy-usb-ppps]: #hdr-mpy-usb-ppps
[mpy-neopixels]: #hdr-mpy-neopixels
[hwctl]: #hdr-hwctl
[nfc-sticker-actions]: #hdr-nfc-sticker-actions
[gif-frames-pack]: #hdr-gif-frames-pack

Repository URLs:

- <https://github.com/mk-fg/hwctl>
- <https://codeberg.org/mk-fg/hwctl>
- <https://fraggod.net/code/git/hwctl>


<a name=hdr-mpy-usb-ppps></a>
## [mpy-usb-ppps](mpy-usb-ppps.py)

Micropython firmware-script used to control USB per-port-power-switching, but NOT
via actual built-in ppps protocol that some USB Hub devices support (and can be done
using sysfs on linux, or [uhubctl] tool), and instead via cheap solid-state-relays,
soldered to a simple USB Hub with push-button power controls on ports.

Hubs with ppps have two deal-breaking downsides for me:

- They're impossible to find or identify - e.g. any model on [uhubctl] list of
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
nothing gets randomly powered-on, and when it does, code on the
microcontroller can be smart enough to know when to shut down devices if
whatever using them stops sending it "this one is still in use" pings.

Implemented using mostly-stateless protocol sending single-byte commands over ttyACM
(usb tty) back-and-forth, so that there can be no "short read" buffering issues.

Script also implements listening to connected push-buttons, as configured in
HWCtlConf at the top, and sending one-byte events for those.

When using mpremote with at least RP2040s, `mpremote run mpy-usb-ppps.py`
won't connect its stdin to the script (at least current 2023 version of it),
so right way to actually run it seem to be uploading as `main.py` and do
`mpremote reset` or something to that effect.

For deploying script as long-term firmware, pre-compiling it via
[mpy-cross tool] is probably a good idea:

``` console
% mpy-cross -march=armv6m -O2 mpy-usb-ppps.py -o usb_ppps.mpy
% mpremote cp usb_ppps.mpy :
% echo 'import usb_ppps; usb_ppps.run()' >loader.py
% mpremote cp loader.py :main.py
% mpremote reset
```

(mpy-cross binary used there is trivial to build - see [Arch PKGBUILD here] -
but copying script itself as main.py will work for autorun just as well)

`loader.py` in that example can also include/pass any config options to run(),
e.g. `run(verbose=True, btn_debounce=0.3)`, to be used as a plaintext
configuration file, without the need to replace main mpy module.

Also wrote-up some extended thoughts on this subject in a
["USB hub per-port power switching done right" blog post].

[uhubctl]: https://github.com/mvp/uhubctl/
[mpy-cross tool]:
  https://github.com/micropython/micropython/tree/master/mpy-cross
[Arch PKGBUILD here]:
  https://github.com/mk-fg/archlinux-pkgbuilds/blob/master/mpy-cross/PKGBUILD
["USB hub per-port power switching done right" blog post]:
  https://blog.fraggod.net/2023/11/17/usb-hub-per-port-power-switching-done-right-with-a-couple-wires.html


<a name=hdr-mpy-neopixels></a>
## [mpy-neopixels](mpy-neopixels.py)

Script to display packed GIF pixel-art animation on a [neopixel] panel
like [Waveshare Pico-RGB-LED] 16x10 WS2812 LED matrix, looping it with
a random intervals a bunch of times. Intended to be used for flashy
visual reminders, from e.g. [nfc-sticker-actions] dispatcher.

[gif-frames-pack] tool below can be used to compress animated GIFs
into a couple lines of base64+zlib strings used in this script.

One way to run the script on device connected over ttyACM without needing it
locally and with any kind of configuration parameters, is to compile it
using mpy-cross (also mentioned above), upload resulting mpy module file,
and invoke it via `mpremote exec` with those parameters in there
(instead of more usual `mpremote run mpy-neopixels.py`):

``` console
## For more space/mem/import-time optimized version:
% mpy-cross -march=armv6m -O2 mpy-neopixels.py -o npx.mpy
% mpremote cp npx.mpy :
## ...or without mpy-cross: mpremote cp mpy-neopixels.py :npx.py

## Import and run with configuration tweaks
% mpremote exec --no-follow 'import npx; npx.run_with_times(td_total=8*60)'
```

All time-delta "td" parameters in addition to a fixed value in seconds accept
lists of TimeDeltaRNG tuples of (chance \[0-1.0\], td-min \[s\], td-max \[s\]),
to roll the chance on each of these in same order until first success,
and then uniformly pick td from min-max range. These values are randomly
picked like that before every inteval/delay, so will vary within single run.

[neopixel]: https://docs.micropython.org/en/latest/library/neopixel.html
[Waveshare Pico-RGB-LED]: https://www.waveshare.com/wiki/Pico-RGB-LED


<a name=hdr-hwctl></a>
## [hwctl](hwctl.py)

Linux userspace part of the control process - a daemon script to talk to
connected microcontrollers, receive button presses and send them commands,
proxied to/from whatever simple unixy IPC mechanisms, like files and FIFOs.

- Receiving button presses from MCU is handled via `-F/--buttons-file` option,
  to output those to a local file, which can be used as a queue, handled via some
  script woken-up by e.g. [systemd.path unit].

    For example, `-F /tmp/btns-lights.log:mode=640:max-bytes=4_000:buttons=1,4-8,11`
    will dump specified buttons to an auto-rotated logfile at that path, with that mode.

    Something similar to `tail -F /tmp/btns-lights.log` can read lines from there.

- Command lines from a local FIFO (as in [mkfifo]) can be read by using
  `-f/--control-fifo` option. Those are parsed and forwarded to connected microcontroller.

    Allows sending those from any shell script using e.g. `echo usb3=on >hwctl.fifo`

    Currently parsed commands are (X=0-15): `usbX=on`, `usbX=off`, `usbX=wdt`,
    which are encoded and sent to [mpy-usb-ppps] script above.

- Can send commands to MCU, mapped to unix signals - via `-s/--control-signal` option.

    Same as with FIFO commands above, with specific signal bound to specific
    command via cli options, e.g. `-s usr1=usb2=on -s usr2=usb2=off`

    Can be used via something like `pkill -USR1 -F hwctl.pid`, allowing to
    set commands on hwctl invocation instead of in the script that triggers those.

Uses serial_asyncio module from [pyserial/pyserial-asyncio] for ttyACMx communication.

[Older version] used to poll /proc/self/mountinfo fd and do some "don't forget
to unmount" indication via LEDs connected to Arduino Uno board (running [hwctl.ino]),
read/debounce physical buttons, as well as similar usb-control wdt logic as
mpy-usb-ppps script.

[mkfifo]: https://man.archlinux.org/man/mkfifo.1
[systemd.path unit]: https://man.archlinux.org/man/systemd.path.5
[pyserial/pyserial-asyncio]: https://github.com/pyserial/pyserial-asyncio
[Older version]: https://github.com/mk-fg/hwctl/blob/0e60923/hwctl.py
[hwctl.ino]: https://github.com/mk-fg/hwctl/blob/0e60923/hwctl.ino


<a name=hdr-nfc-sticker-actions></a>
## [nfc-sticker-actions](nfc-sticker-actions.py)

Script to run configured commands from a simple [INI file] config
(like [nfc-sticker-actions.example.ini]) when an NFC tag/sticker
(e.g. <$0.01 NTAG203/213 ISO14443 tags) with matching UID value
is pressed to a reader pad.

My use-case for this is sticking those cheap NTAGs on household chores/stuff
that's easy to forget about (like a tube of toothpaste to brush teeth before sleep),
and only snooze various notifications when that thing is tapped onto NFC-reader pad,
making it more difficult to forget about it, as disabling notification requires
holding damn thing in your hand already :)

Should be combined with any kind of notification or control/signaling scripts
(e.g. notify-send, [mpy-neopixels] above or [timed-ble-beacon] stuff) to do
something notable on desktop/network or in the physical world via `[action: ...]`
sections in the config file.

Data stored in NFC tag sectors isn't actually read by this script,
as it's enough to tell apart their unique-enough built-in UIDs for its purposes.

Optionally integrates with [hwctl] script above, to activate NFC pad via button,
so that it doesn't stay powered-on needlessly all the time (and start the script
itself via [systemd.path unit] when needed), or to send other commands there,
to e.g. power up/down whatever hardware used in `[action: ...]` sections,
or also to trigger actions via hw buttons directly (without NFC).

Uses [pyscard] module for NFC reader communication, via [PCSC lite] on linux.

[INI file]: https://en.wikipedia.org/wiki/INI_file
[nfc-sticker-actions.example.ini]: nfc-sticker-actions.example.ini
[timed-ble-beacon]:
  https://github.com/mk-fg/fgtk?tab=readme-ov-file#hdr-timed-ble-beacon
[pyscard]: https://github.com/LudovicRousseau/pyscard
[PCSC lite]: https://pcsclite.apdu.fr/


<a name=hdr-gif-frames-pack></a>
## [gif-frames-pack](gif-frames-pack.py)

Helper script to efficiently pack GIF animation frames into an
easy-to-decode and relatively small sequential color arrays to
display via [neopixel] LED matrices (e.g. N-by-M rectangle of WS2812 LEDs),
via e.g. [mpy-neopixels] script above.

For example, it compresses complicated and messy 2,621-byte 16x8 49-frame
animated GIF file down to ~290 bytes, which are much easier to embed into
script as base64 blob and iterate/loop over in python code - moreso than
raw GIF itself anyhow.

Uses [ImageMagick] command-line "magick" tool to extract all necessary data
from gifs (pixel colors, per-frame delays, etc), which seem to have full-featured
parser for those.

[ImageMagick]: https://imagemagick.org/
