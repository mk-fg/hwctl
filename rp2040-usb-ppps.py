# RP2040 micropython fw script to control USB port power pins over ttyACM,
#  using one-byte commands and with a simple watchdog-timeout logic to power them off.

import sys, asyncio, time, machine, collections as cs


class HWCtlConf:

	verbose = False
	wdt_timeout = 4 * 60 # all time-delta values are in int/float seconds
	wdt_slack = 0.5 # added to push sleeps past their target
	btn_check = True # check state after irq to ignore more transient noise
	btn_debounce = 0.7 # ignore irq events within this time-delta

	# Addrs are event id's that get sent over tty, stored in U/B bits (see below)
	usb_hub_ports = dict( # pin=<n> (None=noop), addr=<n || pin>
		hub1_port1=dict(pin=0), hub1_port2=dict(pin=1),
		# hub1_port3= -- does not have a relay, not used here
		hub1_port4=dict(pin=2), hub2_port1=dict(pin=4) )
	button_pins = dict( # pin=<n>, addr=<n || pin>, trigger=<0/1>
		btn1=dict(pin=3, addr=0, trigger=0) )


class USBPortState:

	def __init__(self, port, addr, pin_n, wdt_timeout, log=None):
		self.pin_n, self.pin = ( ('-', None) if pin_n is None else
			(pin_n, machine.Pin(pin_n, machine.Pin.OUT, value=0)) )
		self.port, self.addr, self.log = port, addr, log
		self.pin_st, self.wdt_ts = False, None
		self.wdt_timeout = int(wdt_timeout * 1_000)

	def __repr__(self):
		st = ('OFF', 'ON')[self.pin_st]
		if not self.wdt_ts: wdt_st = 'static'
		else:
			wdt_st = time.ticks_diff(self.wdt_ts, time.ticks_ms())
			wdt_st = ( f'wdt=[ last-ping={wdt_st / 1000:,.1f}s' +
				f' off-in={(self.wdt_timeout - wdt_st) / 1000:,.1f} ]' )
		return f'<USBPortSt {self.port} #{self.addr}@{self.pin_n} {st} {wdt_st}>'

	def set_state(self, enabled):
		self.pin_st = bool(enabled)
		if self.pin: self.pin.value(self.pin_st)
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


class GPIOButtonState:

	def __init__( self, name, addr,
			pin_n, trigger, callback, debounce_td, debounce_check, log=None ):
		self.log, Pin = log, machine.Pin
		self.name, self.addr, self.pin_n, self.trigger = name, addr, pin_n, trigger
		pull, irq = ( (Pin.PULL_UP, Pin.IRQ_FALLING)
			if not trigger else (Pin.PULL_DOWN, Pin.IRQ_RISING) )
		self.debounce = trigger if debounce_check else None, int(debounce_td * 1_000)
		self.ts, self.cb, self.pin = 0, callback, Pin(pin_n, Pin.IN, pull=pull)
		self.pin.irq(self.irq_handler, trigger=irq)

	__repr__ = lambda s: f'<Button {s.name} #{s.addr}@{s.pin_n}={s.trigger}>'

	def irq_handler(self, pin):
		ts, (trigger, td) = time.ticks_ms(), self.debounce
		if time.ticks_diff(ts, self.ts) < td: return
		if trigger is not None and pin.value() != trigger: return
		self.ts = ts; self.log and self.log(f'{self} - pressed'); self.cb(self.addr)


class HWCtl:
	# All commands are 1-byte, and have high bits set to be most distinct from ascii
	# << usb-wdt-ping = 1111 UUUU : U - usb-addr (0-15)
	# << usb-toggle = 110P UUUU : U - usb-addr (0-15), P=0 - disable, P=1 - enable
	# >> ack/err = 111E UUUU : E=0 - ack, E=1 - error
	# >> log/err line prefix byte = 110E UUUU : E=0 - log line, E=1 - err line for U addr
	# >> button press = 1000 BBBB : B - connected button number (0-15)

	def __init__(self, conf, send):
		self.conf, self.send, self.usbs, self.btns = conf, send, dict(), dict()
		self.log = conf.verbose and (lambda msg: self.cmd_send(f'[hwctl] {msg}'))

		port_log = conf.verbose and (lambda msg: self.cmd_send(f'[upst] {msg}'))
		for port, info in conf.usb_hub_ports.items():
			pin_n = info['pin']; addr = info.get('addr', pin_n)
			self.usbs[addr] = USBPortState(port, addr, pin_n, conf.wdt_timeout, log=port_log)

		btn_log = conf.verbose and (lambda msg: self.cmd_send(f'[btn] {msg}'))
		btn_send = lambda addr: self.send(0x80 | addr)
		for btn, info in conf.button_pins.items():
			pin_n = info['pin']; addr = info.get('addr', pin_n)
			self.btns[btn] = GPIOButtonState( btn, addr, pin_n,
				info['trigger'], btn_send, conf.btn_debounce, conf.btn_check, log=btn_log )

		self.log and self.log( 'HWCtl init done:'
			f' {len(self.usbs)} usb port(s), {len(self.btns)} button(s)' )

	_cmd_result = cs.namedtuple('cmd_res', 'addr err')

	def cmd_handle(self, cmd):
		res = self.cmd_parse(cmd)
		self.cmd_send(res.addr, res.err)

	def cmd_parse(self, cmd):
		if not cmd: return self._cmd_result(None, None)
		if cmd & 0b1100_0000 != 0b1100_0000:
			return self._cmd_result( None,
				f'Invalid cmd prefix-bits: {cmd:08b} ({str(cmd.to_bytes(1, "big"))[2:-1]})' )
		cmd, addr = (cmd >> 4) & 0b11, cmd & 0b1111
		if not (wdt := cmd == 0b11):
			if cmd & 0b10: return self._cmd_result(addr, 'Invalid cmd')
			st_enabled = cmd & 1
		try: st = self.usbs[addr]
		except KeyError:
			return self._cmd_result(addr, f'No usb-port set for addr: {addr}')
		try:
			if wdt: st.wdt_ping()
			else: st.set_state(st_enabled)
		except Exception as err:
			return self._cmd_result( addr,
				f'State/GPIO error: [{err.__class__.__name__}] {err}' )
		return self._cmd_result(addr, None)

	def cmd_send(self, addr=None, msg=None):
		'Format ack/err reply for usb-cmd addr or a log message without it'
		if addr is None and not msg: return # no-op cmd_result
		if msg is None and isinstance(addr, str): addr, msg = None, addr
		res = list()
		if addr is not None: # ack/err reply to a command
			if addr <= 0xf:
				cmd = 0b1110_0000 | (bool(msg) << 4) | addr
				res.append(cmd.to_bytes(1, 'big'))
			else: msg = f'Invalid addr for usb ack/err: {addr}'
		if msg:
			cmd = 0b1100_0000 | (err_bit := addr is not None) << 4
			if err_bit: cmd |= addr
			for n, b in enumerate(msg := msg.rstrip().encode()):
				if b > 127: msg[n] = 35 # #-char
			res.append(cmd.to_bytes(1, 'big')); res.append(msg); res.append(b'\n')
		self.send(res)

	def wdt_td(self):
		ts, td_max = time.ticks_ms(), 0xfffffff
		td = min(st.wdt_td(ts, td_max) for st in self.usbs.values())
		return td != td_max and td

	def wdt_check(self):
		ts = time.ticks_ms()
		for st in self.usbs.values(): st.wdt_check(ts)


async def main():
	stdout = asyncio.StreamWriter(sys.stdout, {})
	outq, outq_flag = cs.deque([], 20), asyncio.ThreadSafeFlag()
	def outq_send(data):
		if not data: return
		elif isinstance(data, int): outq.append(bytes([data]))
		elif isinstance(data, bytes): outq.append(data)
		elif isinstance(data, list): outq.extend(data)
		else: outq.append(data.encode())
		outq_flag.set()
	async def _outq_flush():
		while True:
			await outq_flag.wait()
			while outq: stdout.write(outq.popleft())
			if outq: outq_flag.set()
			await stdout.drain()
	outq_task = asyncio.create_task(_outq_flush())

	hwctl = HWCtl(conf := HWCtlConf(), outq_send)
	p_log = conf.verbose and (lambda msg: hwctl.cmd_send(f'[main] {msg}'))
	p_log and p_log('--- scheduler init ---')
	stdin = asyncio.StreamReader(sys.stdin.buffer)
	while True:
		read = stdin.readexactly(1)
		if delay := hwctl.wdt_td():
			delay = conf.wdt_slack + delay / 1_000
			read = asyncio.wait_for(read, delay)
			p_log and p_log(f'wdt-delay wait: {delay:.1f}s')
		else: p_log and p_log('Waiting for tty command...')
		try: cmd = await read
		except asyncio.TimeoutError: hwctl.wdt_check(); continue
		except Exception as err:
			p_log and p_log(f'Error polling input tty [ {err} ], exiting...'); break
		hwctl.cmd_handle(cmd[0])
	outq_task.cancel()
	p_log and p_log('--- scheduler stop ---')

def run(): asyncio.run(main())
if __name__ == '__main__': run()
