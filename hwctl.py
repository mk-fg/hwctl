#!/usr/bin/env python3

import collections as cs, contextlib as cl, itertools as it, pathlib as pl
import os, sys, re, logging, signal, enum, fcntl, stat, time, asyncio

import serial, serial_asyncio # https://github.com/pyserial/pyserial-asyncio

# These events are used for all inputs and outputs in a shared queue
ev_t = enum.Enum( 'Ev',
	'wakeup log err connect disconnect init_cmd fifo_cmd sig_cmd button' )
ev_tuple = cs.namedtuple('Event', 't msg', defaults=[None])

cmd_bits = type('CmdBits', (object,), dict(on=0x10, off=0x00, wdt=0x30))


class SerialProtocol(asyncio.Protocol):
	# All commands are 1-byte, and have high bits set to be most distinct from ascii
	# >> usb-wdt-ping = 1111 UUUU : U - usb-addr (0-15)
	# >> usb-toggle = 110P UUUU : U - usb-addr (0-15), P=0 - disable, P=1 - enable
	# << ack/err = 111E UUUU : E=0 - ack, E=1 - error
	# << log/err line prefix byte = 110E UUUU : E=0 - log line, E=1 - err line for U addr
	# << button press = 1000 BBBB : B - connected button number (0-15)

	transport = None
	def __init__(self, queue):
		self.transport, self.queue, self.ack_wait = asyncio.Event(), queue, None
	def connection_made(self, transport):
		self.log_ev = self.log_buff = None
		ev, self.transport = self.transport, transport; ev.set()
		self.queue.put_nowait(ev_tuple(ev_t.connect))
	def connection_lost(self, exc):
		self.log_ev = self.log_buff = self.transport = None
		self.queue.put_nowait(ev_tuple(ev_t.disconnect))

	def data_received(self, data):
		if self.log_ev:
			buff_ext, data = ( (data[:dn], data[dn+1:])
				if (buff_end := (dn := data.find(b'\n')) != -1) else (data, b'') )
			for n, c in enumerate(buff_ext):
				if c <= 127: continue
				buff_ext, buff_end, data = buff_ext[:n], True, buff_ext[n:] + data
				log.error(
					'[<< ] [%s] non-ascii msg-byte, using as cmd :: %s log_buff_len=%s',
					self.log_ev.name, f'[{c:08b} {str(c.to_bytes(1))[2:-1]}]', len(self.log_buff) + dn )
				break
			log.debug( '[<< ] [%s] line-%s :: %s',
				self.log_ev.name, 'end' if buff_end else 'read', buff_ext )
			self.log_buff += buff_ext
			if not buff_end: return
			self.queue.put_nowait(ev_tuple(
				self.log_ev, self.log_buff.decode(errors='backslashreplace') ))
			self.log_ev = self.log_buff = None

		for n, cmd in enumerate(data, 1):
			log_pre = f'[<< ] [{cmd:08b} {str(cmd.to_bytes(1))[2:-1]}]'
			if cmd & 0xf0 == 0x80:
				self.queue.put_nowait(ev_tuple(ev_t.button, ev := (time.time(), cmd & 0x0f)))
				log.debug('%s button-press: %s', log_pre, ev)
			elif cmd & 0b1100_0000 != 0b1100_0000:
				log.error('%s Invalid cmd prefix-bits', log_pre)
			elif cmd & 0x20:
				st_err, st_ack = cmd & 0x10, '' if self.ack_wait else 'un'
				log.debug('%s %s [%sexpected]', log_pre, 'err' if st_err else 'ack', st_ack)
				if st_err: log.error('%s Failure-response for last command', log_pre)
				if self.ack_wait: self.ack_wait = self.ack_wait.set_result(None)
			else:
				self.log_ev, addr = ev_t.err if cmd & 0x10 else ev_t.log, cmd & 0xf
				log.debug('%s line-event (err-addr=%s): %s', log_pre, addr, self.log_ev.name)
				self.log_buff, data = b'', data[n:]
				break # will run processing of data tail, if any

		else: data = b''
		if data: return self.data_received(data)

	async def send_command(self, cmd, timeout=3):
		cmd |= 0b1100_0000
		log_pre = f'[ >>] [{cmd:08b} {str(cmd.to_bytes(1))[2:-1]}]'
		log.debug('%s send', log_pre)
		if self.ack_wait: raise RuntimeError('Concurrent send_command calls')
		if isinstance(self.transport, asyncio.Event): await self.transport.wait()
		if not self.transport: return log.warning('%s Send after disconnect', log_pre)
		self.transport.write(cmd.to_bytes(1))
		self.ack_wait = asyncio.Future()
		try: await asyncio.wait_for(self.ack_wait, timeout=timeout)
		except asyncio.TimeoutError: log.error('%s Timeout on ack/err', log_pre)
		finally: self.ack_wait = None


async def run(events, dev, btns, sigs, init_cmds, daemon_tasks=None):
	loop = asyncio.get_running_loop()
	transport, proto = ( await serial_asyncio
		.connection_for_serial(loop, lambda: SerialProtocol(events), dev) )

	_proto_cmd_lock = asyncio.Lock()
	async def _proto_cmd_send(cmd):
		async with _proto_cmd_lock: await proto.send_command(cmd)
	def proto_cmd_send(cmd, cmd_info=None, wakeup=False):
		if cmd_info: log.info('cmd :: %s', cmd_info)
		tasks.add(asyncio.create_task(_proto_cmd_send(cmd), name='cmd-send'))
		if wakeup: events.put_nowait(ev_tuple(ev_t.wakeup)) # if not from handler loop

	sig_cmd_send = lambda cmd: events.put_nowait(ev_tuple(ev_t.sig_cmd, cmd))
	for sig, cmd in sigs.items(): loop.add_signal_handler(sig, sig_cmd_send, cmd)
	for cmd in init_cmds: events.put_nowait(ev_tuple(ev_t.init_cmd, cmd))

	tasks = {asyncio.create_task(events.get(), name='ev')}
	tasks.update( asyncio.create_task(task, name=name)
		for name, task in (daemon_tasks or dict()).items() if task )
	while True:
		# log.debug('[---] tasks: %s', ' '.join(t.get_name() for t in tasks))
		done, tasks = await asyncio.wait(
			tasks, return_when=asyncio.FIRST_COMPLETED )
		for task in done:
			task, ev = task.get_name(), await task
			log.debug('[-ev] %s/%s %s', task, len(tasks), ev or '-')
			if task not in ['ev', 'cmd-send']: raise RuntimeError(f'Daemon task failed: {task}')
			if task == 'ev': tasks.add(asyncio.create_task(events.get(), name='ev'))
			else: continue

			if ev.t is ev_t.wakeup: pass
			elif ev.t is ev_t.log: log.info('fw-log :: %s', ev.msg)
			elif ev.t is ev_t.err: log.error(f'mcu-err :: %s', ev.msg)
			elif ev.t is ev_t.disconnect: return log.error('mcu disconnected, exiting...')
			elif ev.t in [ev_t.fifo_cmd, ev_t.sig_cmd, ev_t.init_cmd]:
				cmd_t = 'fifo' if ev.t is ev_t.fifo_cmd else 'sig'
				if not (m := re.fullmatch(r'usb(\d+)=(on|off|wdt)', ev.msg)):
					log.error('%s-cmd :: unrecognized - %r', cmd_t, ev.msg); continue
				if (addr := int(m[1])) > 0xf:
					log.error('%s-cmd :: usb-addr out of range - %s', cmd_t, m[1]); continue
				proto_cmd_send(getattr(cmd_bits, m[2]) | addr, ev.msg)
			elif ev.t is ev_t.button:
				log.info('button-press :: time=%s button=%s', *ev.msg)
				for q in btns: q.put_nowait(ev.msg)


async def fifo_read_loop(p, mode, queue):
	'Reads space-separated cmds from speficied fifo path into queue'
	buff = eof = None
	def _ev():
		nonlocal buff, eof
		buff += (chunk := src.read())
		if not chunk: buff += b'\n' # make sure to process last cmd
		while m := re.search(rb'\s+', buff):
			cmd, buff = buff[:m.start()], buff[m.end():]
			if cmd: queue.put_nowait(ev_tuple(
				ev_t.fifo_cmd, cmd.decode(errors='backslashreplace') ))
		if not chunk: eof.set_result(None)
	try_mkfifo, loop = False, asyncio.get_running_loop()
	while True: # creating/opening fifo is full of race conditions
		if try_mkfifo:
			(p_tmp := p.parent / (p.name + f'.new.{os.getpid()}')).unlink(missing_ok=True)
			os.mkfifo(p_tmp, mode or 0o666)
			if mode: p_tmp.chmod(mode, follow_symlinks=False)
			p_tmp.rename(p); try_mkfifo = False
		try: fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK)
		except FileNotFoundError: try_mkfifo = True; continue
		if not stat.S_ISFIFO(os.stat(fd).st_mode):
			os.close(fd); p.unlink(missing_ok=True); try_mkfifo = True; continue
		with open(fd, 'rb') as src:
			buff, eof = b'', asyncio.Future()
			loop.add_reader(fd, _ev)
			try: await eof
			finally: loop.remove_reader(fd)

async def file_logger_loop(p, queue, buttons=None, mode=0, max_bytes=0, bak_count=1):
	'Append button-press lines to auto-rotated file from a queue of (ts, btn_n) tuples.'
	file_list = [p] + list(pl.Path(f'{p}.{n}') for n in range(1, bak_count+1))
	dst = dst_id = None
	def _dst_init_check():
		nonlocal dst, dst_id; reopen = not dst
		try: st = p.stat()
		except FileNotFoundError: st = None
		if reopen := not (dst_id and st and dst_id == (st.st_dev, st.st_ino)):
			log.debug('Opening (re-)moved/new buttons log-file: %s', p)
		elif reopen := max_bytes and st and st.st_size >= max_bytes:
			log.debug( 'Rotating buttons log-file due to size'
				' limit (%d >= %d): %s', st.st_size, max_bytes, p )
			for b, a in it.pairwise(reversed(file_list)):
				with cl.suppress(FileNotFoundError): a.rename(b)
		if reopen:
			dst = open(os.open( p, os.O_WRONLY |
				os.O_APPEND | os.O_CREAT, 0o777 if not mode else 0 ), 'a')
			if mode: os.chmod(dst.fileno(), mode)
			st = os.stat(dst.fileno()); dst_id = st.st_dev, st.st_ino
	try:
		while True:
			ts, btn = await queue.get()
			if buttons and btn not in buttons: continue
			_dst_init_check(); dst.write(f'{ts} btn={btn}\n'); dst.flush()
	finally:
		if dst: dst.close()


def main(args=None):
	import argparse, textwrap
	dd = lambda text: re.sub( r' \t+', ' ',
		textwrap.dedent(text).strip('\n') + '\n' ).replace('\t', '  ')
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawTextHelpFormatter, usage='%(prog)s [opts]',
		description='Script to send commands over tty to usb-connected microcontrollers.')
	parser.add_argument('-d', '--tty-dev', metavar='dev', default='/dev/ttyACM0',
		help='tty device node for communicating with an mcu board. Default: %(default)s')
	parser.add_argument('-b', '--baud-rate', metavar='rate', default=115200,
		help='Baud rate for tty device communication. Default: %(default)s')
	parser.add_argument('-f', '--control-fifo', metavar='path[:mode]', help=dd('''
		Path to create fifo to read control commands from, space/line-separated.
		Optional octal mode-suffix can be added to chmod fifo, e.g.: -f ctl.fifo:660
		Supported commands (X=0-15): usbX=on, usbX=off, usbX=wdt.'''))
	parser.add_argument('-s', '--control-signal', metavar='sig=cmd', action='append', help=dd('''
		Interprets specified unix signal(s) as -f/--control-fifo commands.
		For example: -s usr1=usb2=on -s usr2=usb2=off. Can be used multiple times.'''))
	parser.add_argument('-c', '--init-cmd', metavar='cmd', action='append', help=dd('''
		Run specified commands on script start, and warn if they don't get ACKed properly.
		Commands use same format as with -f/--control-fifo option. Can be used multiple times.'''))
	parser.add_argument('-F', '--buttons-file',
		metavar='path[:opts]', action='append', help=dd('''
			Path to an output file to append connected button presses to, one per line.
			Can be specified multiple times, and have ":options" suffix,
				to control which buttons to write to which file, and their rotation parameters.
			":options" suffix can have following :-separated options, in any order:
				- max-bytes=<int> - rotate file on reaching that size. Default = 0 - never.
				- bak-count=<int> - keep N files with .1, .2, ... suffix after rotation. Default = 1.
				- mode=<octal> - chmod output file(s) to mode, e.g. 640. Default = 0 - disabled.
				- buttons=<int>[-<int>][,...] - only output specified comma/space-separated
						button events into this file, with -N meaning "don't output N". Default = all.
			Usage examples with options (multiple files can be used at the same time):
				-F /tmp/btns-all.log:mode=600:max-bytes=8_000:bak-count=3
				-F /tmp/btns-lights.log:mode=640:max-bytes=4_000:buttons=1,4-8,11
			Files only get opened/rotated when there's some output there.'''))
	parser.add_argument('-p', '--pid-file',
		metavar='file', help='File to write pid into, for signaling and deduplication.')
	parser.add_argument('-v', '--verbose',
		action='store_true', help='Verbose operation mode.')
	parser.add_argument('--debug',
		action='store_true', help='Print tty traffic in addition to -v/--verbose info.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	if opts.debug: log = logging.DEBUG
	else: log = logging.INFO if opts.verbose else logging.WARNING
	logging.basicConfig( level=log, style='{',
		format='{levelname:5} :: {message}', datefmt='%Y-%m-%dT%H:%M:%S' )
	log = logging.getLogger('hwctl')

	tasks, events = dict(), asyncio.Queue()
	init_cmds = opts.init_cmd or list()

	sigs = dict()
	for n, opt in enumerate(opts.control_signal or list()):
		try:
			sig, _, cmd = opt.partition('=')
			sig = getattr(signal, f'SIG{sig.upper()}')
			if not cmd: raise ValueError
		except: parser.error(f'Invalid -s/--control-signal spec: {opt}')
		sigs[sig] = cmd

	btn_opts = dict(
		max_bytes=int, bak_count=int, mode=lambda s: int(s, 8),
		buttons=lambda s: set(it.chain.from_iterable(
			range(int(n.split('-', 1)[0]), int(n.split('-', 1)[1])+1)
				if '-' in n else [int(n)] for n in s.replace(',', ' ').split() )) )
	for n, opt in enumerate(btns := list(opts.buttons_file or list())):
		p, _, s = opt.partition(':'); kws = dict()
		while s.strip():
			k = v = None; k, _, s = s.partition(':'); k, _, v = k.partition('=')
			try:
				if not (k and v): raise ValueError
				k = k.replace('-', '_'); v = btn_opts[k](v)
			except: parser.error(f'Invalid -F/--buttons-file options in: {opt}')
			else: kws[k] = v
		btns[n], tasks[f'btn-file-{n}:{p}'] = ( (q := asyncio.Queue()),
			file_logger_loop((p := pl.Path(p).expanduser()), q, **kws) )

	if opts.control_fifo:
		fifo, _, mode = opts.control_fifo.rpartition(':')
		tasks['fifo'] = fifo_read_loop(pl.Path(fifo), int(mode or '0', 8), events)

	with cl.ExitStack() as ctx:
		if pid := opts.pid_file and pl.Path(opts.pid_file):
			pid_file = ctx.enter_context(open(os.open(
				opts.pid_file, os.O_RDWR | os.O_CREAT, 0o600 ), 'r+b', 0))
			fcntl.lockf(pid_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
			pid_file.seek(0); pid_file.write(f'{os.getpid()}\n'.encode()); pid_file.truncate()
			ctx.callback(lambda: pid.unlink(missing_ok=True))
		dev = ctx.enter_context(serial.Serial(opts.tty_dev, opts.baud_rate, timeout=1.0))
		try: return asyncio.run(run(events, dev, btns, sigs, init_cmds, tasks))
		except asyncio.CancelledError: pass

if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	sys.exit(main())
