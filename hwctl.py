#!/usr/bin/env python3

import collections as cs, contextlib as cl, pathlib as pl
import os, sys, re, logging, signal, enum, fcntl, stat, asyncio

import serial, serial_asyncio # https://github.com/pyserial/pyserial-asyncio

ev_t = enum.Enum('Ev', 'wakeup log err connect disconnect fifo_cmd')
ev_tuple = cs.namedtuple('Event', 't msg', defaults=[None])

cmd_bits = type('CmdBits', (object,), dict(on=0x10, off=0x00, wdt=0x30))
signal_cmds = dict(usr1=cmd_bits.on | 1, usr2=cmd_bits.off | 1, quit=cmd_bits.wdt | 0)


class SerialProtocol(asyncio.Protocol):
	# All commands are 1-byte, and have high bits set to be most distinct from ascii
	# >> usb-wdt-ping = 1111 UUUU : U - usb-addr (0-15)
	# >> usb-toggle = 110P UUUU : U - usb-addr (0-15), P=0 - disable, P=1 - enable
	# << ack/err = 111E UUUU : E=0 - ack, E=1 - error
	# << log/err line prefix byte = 110E UUUU : E=0 - log line, E=1 - err line for U addr

	transport = None
	def __init__(self, queue):
		self.queue, self.ack_wait = queue, None
	def connection_made(self, transport):
		self.log_ev = self.log_buff = None
		self.transport = transport
		self.queue.put_nowait(ev_tuple(ev_t.connect))
	def connection_lost(self, exc):
		self.log_ev = self.log_buff = None
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

			if cmd & 0b1100_0000 != 0b1100_0000:
				log.error('%s Invalid cmd prefix-bits', log_pre)
				continue

			if cmd & 0x20:
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
		self.transport.write(cmd.to_bytes(1))
		self.ack_wait = asyncio.Future()
		try: await asyncio.wait_for(self.ack_wait, timeout=timeout)
		except asyncio.TimeoutError: log.error('%s Timeout on ack/err', log_pre)
		finally: self.ack_wait = None


async def run(events, dev, daemon_tasks=None):
	loop = asyncio.get_running_loop()
	transport, proto = ( await serial_asyncio
		.connection_for_serial(loop, lambda: SerialProtocol(events), dev) )

	_proto_cmd_lock = asyncio.Lock()
	async def _proto_cmd_send(cmd):
		async with _proto_cmd_lock: await proto.send_command(cmd)
	def proto_cmd_send(cmd):
		tasks.add(asyncio.create_task(_proto_cmd_send(cmd), name='cmd-send'))
		events.put_nowait(ev_tuple(ev_t.wakeup))

	for k, cmd in signal_cmds.items():
		loop.add_signal_handler(
			getattr(signal, f'SIG{k.upper()}'), proto_cmd_send, cmd )

	tasks = {asyncio.create_task(events.get(), name='ev')}
	tasks.update( asyncio.create_task(task, name=name)
		for name, task in (daemon_tasks or dict()).items() )
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
			elif ev.t is ev_t.fifo_cmd:
				if not (m := re.fullmatch(r'usb(\d+)=(on|off|wdt)', ev.msg)):
					log.error('fifo-cmd :: unrecognized - %r', ev.msg); continue
				if (addr := int(m[1])) > 0xf:
					log.error('fifo-cmd :: usb-addr out of range - %s', m[1]); continue
				proto_cmd_send(getattr(cmd_bits, m[2]) | addr)


async def fifo_read_loop(p, queue):
	'Reads space-separated cmds from speficied fifo path into queue'
	loop = asyncio.get_running_loop()

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

	fifo_flags = os.O_RDONLY | os.O_NONBLOCK
	while True:
		with open(fd := os.open(p, fifo_flags), 'rb') as src:
			buff, eof = b'', asyncio.Future()
			loop.add_reader(fd, _ev)
			await eof
			loop.remove_reader(fd)


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
	parser.add_argument('-f', '--control-fifo', metavar='path', help=dd('''
		Path to create fifo to read control commands from, space/line-separated.
		Supported commands (X=0-15): usbX=on, usbX=off, usbX=wdt.'''))
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

	with cl.ExitStack() as ctx:
		events = asyncio.Queue()

		if pid := opts.pid_file and pl.Path(opts.pid_file):
			pid_file = ctx.enter_context(open(os.open(
				opts.pid_file, os.O_RDWR | os.O_CREAT, 0o600 ), 'r+b', 0))
			fcntl.lockf(pid_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
			pid_file.seek(0); pid_file.write(f'{os.getpid()}\n'.encode()); pid_file.truncate()
			ctx.callback(lambda: pid.unlink(missing_ok=True))

		if opts.control_fifo:
			try:
				if p_exists := (p := pl.Path(opts.control_fifo)).stat():
					if not stat.S_ISFIFO(p_exists.st_mode):
						parser.error(f'-f/--control-fifo path already exists, but not a FIFO: {p}')
			except FileNotFoundError: p_exists = None
			if not p_exists: os.mkfifo(p)
			fifo_task = fifo_read_loop(p, events)
		else: fifo_task = None

		dev = ctx.enter_context(serial.Serial(opts.tty_dev, opts.baud_rate, timeout=1.0))
		try: return asyncio.run(run(events, dev, dict(fifo=fifo_task)))
		except asyncio.CancelledError: pass

if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	sys.exit(main())
