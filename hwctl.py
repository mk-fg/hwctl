#!/usr/bin/env python3

import collections as cs, contextlib as cl, pathlib as pl
import os, sys, signal, enum, fcntl, logging, asyncio

import serial, serial_asyncio # https://github.com/pyserial/pyserial-asyncio

ev_t = enum.Enum('Ev', 'log err connect disconnect')
ev_tuple = cs.namedtuple('Event', 't msg', defaults=[None])

signal_cmds = dict(
	usr1=0x10 | 1, usr2=0x10 | 2, quit=0x10 | 3 )


class SerialProtocol(asyncio.Protocol):
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

	def crc3(self, msg, bits=4):
		crc = msg & (2**bits - 1)
		for n in range(bits): crc = (crc >> 1) ^ 6 if crc & 1 else crc >> 1
		return crc

	def data_received(self, data):
		if self.log_ev:
			self.log_buff += data
			if (n := self.log_buff.find(b'\n')) != -1:
				log.debug('[<< ] [%s] line-end :: %s', self.log_ev.name, data.split(b'\n', 1)[0])
				line, data = self.log_buff[:n], self.log_buff[n+1:]
				self.queue.put_nowait(ev_tuple(
					self.log_ev, line.decode(errors='backslashreplace') ))
				self.log_ev = self.log_buff = None
			else: return log.debug('[<< ] [%s] line-read :: %s', self.log_ev.name, data)

		for n, cmd in enumerate(data, 1):
			log_pre = f'[<< ] [{cmd:08b}]'
			if cmd >> 5 != self.crc3(cmd):
				log.debug('%s Discarding: CRC3 mismatch', log_pre)
				continue

			if cmd & 0x10:
				st_err = cmd & 0b1000
				st_ack = 'expected' if self.ack_wait else 'unexpected'
				log.debug('%s %s [%s]', log_pre, 'err' if st_err else 'ack', st_ack)
				if st_err: log.error('Failure-response for last command')
				if self.ack_wait: self.ack_wait = self.ack_wait.set_result(None)

			elif cmd & 0x10 == 0:
				self.log_ev = ev_t.err if cmd & 0b1000 else ev_t.log
				log.debug('%s line-event: %s', log_pre, self.log_ev.name)
				self.log_buff, data = b'', data[n:]
				break # will run processing of data tail, if any

		else: data = b''
		if data: return self.data_received(data)

	async def send_command(self, cmd, timeout=3):
		cmd |= self.crc3(cmd) << 5
		log.debug('[ >>] [%s]', f'{cmd:08b}')
		if self.ack_wait: raise RuntimeError('Concurrent send_command calls')
		self.transport.write(bytes([cmd]))
		self.ack_wait = asyncio.Future()
		try: await asyncio.wait_for(self.ack_wait, timeout=timeout)
		except asyncio.TimeoutError:
			log.error('Timeout on ack/err for cmd [%s]', f'{cmd:08b}')
		finally: self.ack_wait = None


async def run(dev):
	events, loop = asyncio.Queue(), asyncio.get_running_loop()
	transport, proto = await serial_asyncio\
		.connection_for_serial(loop, lambda: SerialProtocol(events), dev)

	_proto_cmd_lock = asyncio.Lock()
	async def _proto_cmd_send(cmd):
		async with _proto_cmd_lock: await proto.send_command(cmd)
	proto_cmd_send = lambda cmd: tasks.add(
		asyncio.create_task(_proto_cmd_send(cmd), name='cmd') )

	for k, cmd in signal_cmds.items():
		loop.add_signal_handler(
			getattr(signal, f'SIG{k.upper()}'), proto_cmd_send, cmd )

	tasks = [asyncio.create_task(events.get(), name='ev')]
	while True:
		# log.debug('[---] tasks: %s', ' '.join(t.get_name() for t in tasks))
		done, tasks = await asyncio.wait(
			tasks, return_when=asyncio.FIRST_COMPLETED )
		for task in done:
			task, ev = task.get_name(), await task
			log.debug('[-ev] %s/%s %s', task, len(tasks), ev or '-')
			if task not in ['ev', 'cmd']:
				raise RuntimeError(f'Background task failed: {task}')
			if task == 'ev': tasks.add(asyncio.create_task(events.get(), name='ev'))
			if ev.t is ev_t.log: log.info('fw-log :: %s', ev.msg)
			elif ev.t is ev_t.err: log.error(f'mcu-err :: %s', ev.msg)
			elif ev.t is ev_t.disconnect: return log.error('mcu disconnected, exiting...')


def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='Script to send commands over tty to usb-connected microcontrollers.')
	parser.add_argument('-d', '--tty-dev',
		metavar='dev', default='/dev/ttyACM0',
		help='tty device node for communicating with an mcu board. Default: %(default)s')
	parser.add_argument('-b', '--baud-rate', metavar='rate', default=115200,
		help='Baud rate for tty device communication. Default: %(default)s')
	parser.add_argument('-p', '--pid-file',
		metavar='file', help='File to write pid into, for signaling.')
	parser.add_argument('-v', '--verbose',
		action='store_true', help='Verbose operation mode.')
	parser.add_argument('--debug', action='store_true',
		help='Print network traffic in addition to -v/--verbose.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	if opts.debug: log = logging.DEBUG
	else: log = logging.INFO if opts.verbose else logging.WARNING
	logging.basicConfig( level=log, style='{',
		format='{levelname:5} :: {message}', datefmt='%Y-%m-%dT%H:%M:%S' )
	log = logging.getLogger('hwctl')

	with cl.ExitStack() as ctx:
		if pid := opts.pid_file and pl.Path(opts.pid_file):
			pid_file = ctx.enter_context(open(os.open(
				opts.pid_file, os.O_RDWR | os.O_CREAT, 0o600 ), 'r+b', 0))
			fcntl.lockf(pid_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
			pid_file.seek(0); pid_file.write(f'{os.getpid()}\n'.encode()); pid_file.truncate()
			ctx.callback(lambda: pid.unlink(missing_ok=True))

		dev = ctx.enter_context(serial.Serial(opts.tty_dev, opts.baud_rate, timeout=1.0))
		try: return asyncio.run(run(dev))
		except asyncio.CancelledError: pass

if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	sys.exit(main())
