# RP2040 micropython fw script to control USB port power pins over ttyACM,
#  using one-byte commands and with a simple watchdog-timeout logic to power them off.

import sys, select, time, machine, collections as cs


class HWCtlConf:

	verbose = False
	wdt_timeout = 4 * 60 * 1_000
	wdt_slack = 500 # added to push sleeps past their target
	poll_noop_delay = 5 * 60 * 1_000

	usb_hub_pins = dict(
		hub1_port1 = 2, hub1_port3 = 3, hub1_port4 = 4,
		# hub1_port2 = x, -- does not have a relay, not used here
		hub2_port1 = 5 )

	usb_hub_addrs = dict( # addresses sent in commands over tty
		hub1_port1 = 0, hub1_port3 = 1, hub1_port4 = 2,
		hub2_port1 = 3 )


class USBPortState:

	def __init__(self, port, addr, pin_n, wdt_timeout, log=None):
		self.port, self.addr, self.pin_n, self.log = port, addr, pin_n, log
		self.pin = machine.Pin(pin_n, machine.Pin.OUT, pull=None, value=0)
		self.pin_st, self.wdt_ts, self.wdt_timeout = False, None, wdt_timeout

	def __repr__(self):
		st = ('OFF', 'ON')[self.pin_st]
		if not self.wdt_ts: wdt_st = 'static'
		else:
			wdt_st = time.ticks_diff(self.wdt_ts, time.ticks_ms())
			wdt_st = ( f'wdt.[ last-ping={wdt_st / 1000:,.1f}s' +
				f' off-in={(self.wdt_timeout - wdt_st) / 1000:,.1f} ]' )
		return f'<USBPortSt {self.port} #{self.addr}@{self.pin_n} {st} {wdt_st}>'

	def set_state(self, enabled):
		self.pin_st = bool(enabled)
		self.pin.value(self.pin_st)
		if not self.pin_st: self.wdt_ts = None
		self.log and self.log(f'{self} - state update')

	def wdt_ping(self):
		self.wdt_ts = time.ticks_ms()
		if not self.pin_st: self.set_state(1)
		self.log and self.log(f'{self} - wdt-ping')

	def wdt_td(self, ts, default=None):
		if self.wdt_ts is None: return default
		return self.wdt_timeout - time.ticks_diff(ts, self.wdt_ts)

	def wdt_check(self, ts=None):
		if not ts: ts = time.ticks_ms()
		if (td := self.wdt_td(ts)) is None: return
		if td <= 0: self.set_state(0)


class HWCtl:

	# All commands are 1-byte, and start with CRC3 calculated over last 4 (not 5!) bits
	# << usb-wdt-ping = CCC1 UUUU : UUU - usb-idx (0-15)
	# << usb-toggle = CCC0 PUUU : UUU - usb-idx (0-7), P=0 - disable, P=1 - enable
	# >> ack/err = CCC1 SUUU : S=0 - ack, S=1 - error
	# >> log/err line prefix byte = CCC0 SUUU : S=0 - log line, S=1 - err line for UUU addr

	cmd_result = cs.namedtuple('cmd_res', 'addr err')

	def __init__(self, conf):
		self.conf, self.usbs = conf, dict() # addr -> usb_port_state
		self.log = conf.verbose and (lambda msg: self.cmd_send(msg=f'[hwctl] {msg}'))
		port_log = conf.verbose and (lambda msg: self.cmd_send(msg=f'[upst] {msg}'))
		for port, pin_n in conf.usb_hub_pins.items():
			addr = conf.usb_hub_addrs[port]
			self.usbs[addr] = USBPortState(port, addr, pin_n, conf.wdt_timeout, log=port_log)
		self.crc3_4b_table = bytearray(self.crc3(n) for n in range(0x10))
		self.crc3 = lambda msg: self.crc3_4b_table[msg & 0xf]
		self.log and self.log(f'HWCtl init done: {len(self.usbs)} usb port(s)')

	def crc3(self, msg, bits=4):
		crc = msg & (2**bits - 1)
		for n in range(bits): crc = (crc >> 1) ^ 6 if crc & 1 else crc >> 1
		return crc

	def cmd_handle(self, cmd):
		if not cmd: return self.cmd_result(None, None)
		if cmd >> 5 != self.crc3(cmd):
			return self.cmd_result(None, f'Invalid cmd-tail CRC3: {cmd:08b}')
		cmd, addr = cmd & 0b1_1000, cmd & 0b0111
		if not (wdt := cmd & 0x10): st_enabled = cmd & 0b1000
		try: st = self.usbs[addr]
		except KeyError:
			return self.cmd_result(addr, f'No usb-port set for addr: {addr}')
		try:
			if wdt: st.wdt_ping()
			else: st.set_state(st_enabled)
		except Exception as err:
			return self.cmd_result( addr,
				f'State/GPIO error: [{err.__class__.__name__}] {err}' )
		return self.cmd_result(addr, None)

	def cmd_send(self, addr=None, msg=None):
		if not addr and not msg: return # no-op cmd_result
		dst = sys.stdout.buffer
		if addr is not None: # ack/err reply to a command
			if addr > 0b0111: raise ValueError(addr)
			cmd = 0x10 | (bool(msg) << 3) | addr
			cmd |= self.crc3(cmd) << 5
			dst.write(chr(cmd))
		if msg: # crc3(0) = 0, so log lines are prefixed by \0
			cmd = (addr_bit_set := addr is not None) << 3
			if addr_bit_set: cmd |= addr
			cmd |= self.crc3(cmd) << 5
			dst.write(chr(cmd))
			dst.write(msg.rstrip().encode())
			dst.write(b'\n')

	def wdt_td(self):
		ts, td_max = time.ticks_ms(), 0xfffffff
		td = min(st.wdt_td(ts, td_max) for st in self.usbs.values())
		return int(td) if td != td_max else 0

	def wdt_check(self):
		ts = time.ticks_ms()
		for st in self.usbs.values(): st.wdt_check(ts)


def main():
	hwctl = HWCtl(conf := HWCtlConf())
	p_log = conf.verbose and (
		lambda msg: hwctl.cmd_send(msg=f'[main] {msg}') )

	poller = select.poll()
	poller.register(sys.stdin.buffer, select.POLLIN)
	ev_err = select.POLLHUP | select.POLLERR

	p_log and p_log('--- main init ---')
	while True:
		delay = conf.wdt_slack + (hwctl.wdt_td() or conf.poll_noop_delay)
		p_log and p_log(f'Poll delay: {delay:,d}')
		if not (ev := poller.poll(delay)): # poll timeout
			hwctl.wdt_check()
			continue
		if ev[0][1] & ev_err or not ev[0][1] & select.POLLIN:
			p_log and p_log('Error polling input tty, exiting...')
			break
		if cmd := sys.stdin.buffer.read(1):
			res = hwctl.cmd_handle(cmd[0])
			hwctl.cmd_send(res.addr, res.err)
	p_log and p_log('--- main stop ---')

run = main
if __name__ == '__main__': main()
