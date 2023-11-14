#!/usr/bin/env python3

import contextlib as cl, functools as ft, pathlib as pl
import os, sys, signal, select, enum, time, fcntl, asyncio
import asyncio

import serial, serial_asyncio # https://github.com/pyserial/pyserial-asyncio

p = lambda *a: None
p_err = lambda s, *sx: print(f'ERROR: {s}', *sx, file=sys.stderr, flush=True)
err_fmt = lambda err: f'[{err.__class__.__name__}] {err}'


class cmd(enum.IntEnum):
	ack = 0
	error = 1

	idle = 0b0100
	busy = 0b0110
	mounted = 0b1000

	status = 0b00010000
	unmount = 0b00100000
	usb_sw = 0b00001110

	connect = 255 + 1
	disconnect = 255 + 2
	mp_mount = 255 + 3
	mp_umount = 255 + 4

st = enum.Enum('State', 'init mounted unmounting unmounted')


class SerialProtocol(asyncio.Protocol):
	transport = None
	def __init__(self, queue):
		self.queue, self.ack_wait = queue, None

	def connection_made(self, transport):
		self.transport, self.buff = transport, b''
		self.queue.put_nowait(cmd.connect)
	def connection_lost(self, exc):
		self.buff = self.queue.put_nowait(cmd.disconnect)

	def data_received(self, data):
		for c in data:
			try: ce = cmd(c)
			except ValueError:
				p_err(f'Unrecognized command byte from mcu: {c}')
				continue
			ack_info = ( '' if ce != cmd.ack else
				' [{}]'.format('expected' if self.ack_wait else 'unexpected') )
			p(f'[<< ] [{c}] {ce.name}{ack_info}')
			if ce != cmd.ack: return self.queue.put_nowait(ce)
			if self.ack_wait: self.ack_wait = self.ack_wait.set_result(None)

	async def send_command(self, ce, timeout=3):
		p(f'[ >>] [{ce.value}] {ce.name}')
		if self.ack_wait: raise RuntimeError('Concurrent send_command calls')
		self.transport.write(bytes([ce.value]))
		self.ack_wait = asyncio.Future()
		try: await asyncio.wait_for(self.ack_wait, timeout=timeout)
		except asyncio.TimeoutError: p_err(f'Timeout sending {ce.name}')
		finally: self.ack_wait = None


def watch_mp_state(loop, queue, mp, poll_timeout):
	with cl.closing(select.epoll()) as poller, open('/proc/self/mountinfo', 'rb') as src:
		poller.register(src.fileno(), select.EPOLLPRI | select.EPOLLERR)
		mounted_last, mp, pid = None, mp.encode(), os.getpid()
		while True:
			mounted = True
			src.seek(0)
			for line in src:
				if line.split()[4] != mp: continue
				break
			else: mounted = False
			if mounted_last is not mounted:
				mounted_last = mounted
				loop.call_soon_threadsafe( queue.put_nowait,
					cmd.mp_mount if mounted else cmd.mp_umount )
			poller.poll(poll_timeout)


async def run_umount(mp):
	proc = await asyncio.create_subprocess_exec('umount', mp)
	code = await proc.wait()
	if code != 0: return p_err(f'umount command failed with code={code}')
	return cmd.mp_umount

async def run(*args, **kws):
	try: await run_sub(*args, **kws)
	except BaseException as err:
		import traceback
		traceback.print_exc()
		p_err(f'main loop failure - {err}')
	os._exit(1) # note: asyncio + threading does not work too well together

async def run_sub( dev, mp,
		mount_recheck_interval=30, xdpms_recheck_interval=30*60 ):
	state, events, loop = st.init, asyncio.Queue(), asyncio.get_running_loop()
	transport, proto = await serial_asyncio\
		.connection_for_serial(loop, lambda: SerialProtocol(events), dev)

	_proto_cmd_lock = asyncio.Lock()
	async def _proto_cmd_send(cmd):
		async with _proto_cmd_lock: await proto.send_command(cmd)
	proto_cmd_send = lambda cmd: tasks.add(
		asyncio.create_task(_proto_cmd_send(cmd), name='cmd') )

	usb_sw = ft.partial(proto_cmd_send, cmd.usb_sw)
	loop.add_signal_handler(signal.SIGQUIT, usb_sw)

	tasks = [ asyncio.create_task(events.get(), name='ev'),
		asyncio.create_task(asyncio.to_thread( watch_mp_state,
			loop, events, mp, mount_recheck_interval ), name='watch_mp') ]

	while True:
		p('--- [{}]'.format(' '.join(t.get_name() for t in tasks)))
		done, tasks = await asyncio.wait(
			tasks, return_when=asyncio.FIRST_COMPLETED )
		state0 = state
		for task in done:
			task, ev = task.get_name(), await task
			p(f'[-ev] {task}/{len(tasks)} {ev and ev.name}')
			if task not in ['ev', 'cmd', 'umount']:
				raise RuntimeError(f'Background task failed: {task}')
			if task == 'ev': tasks.add(asyncio.create_task(events.get(), name='ev'))

			if ev == cmd.mp_mount:
				proto_cmd_send(cmd.mounted)
				state = st.mounted
			elif ev == cmd.mp_umount:
				# umount can flush/exit way after mountinfo changes
				if state != st.unmounting or task == 'umount':
					proto_cmd_send(cmd.idle)
					state = st.unmounted

			elif ev == cmd.status:
				if state == st.unmounting: proto_cmd_send(cmd.busy)
				else: proto_cmd_send(cmd.mounted if state == st.mounted else cmd.idle)
			elif ev == cmd.unmount:
				if state == st.mounted:
					proto_cmd_send(cmd.busy)
					tasks.add(asyncio.create_task(run_umount(mp), name='umount'))
					state = st.unmounting
			elif ev == cmd.error: p_err('got error response from mcu')
			elif ev == cmd.disconnect: return p_err('disconnected from mcu, exiting')

			if state != state0:
				p(f'[st-] :: {state0.name} -> {state.name}')
				state0 = state


def termios_hupcl_disable(fd):
	# Disable HUPCL cflag to avoid resetting MCU on every connection
	# This is needed because DTR line resets arduino and it goes up on open()
	import termios
	iflag, oflag, cflag, lflag, ispeed, ospeed, cc = termios.tcgetattr(fd)
	cflag &= ~termios.HUPCL
	termios.tcsetattr( fd, termios.TCSANOW,
		[iflag, oflag, cflag, lflag, ispeed, ospeed, cc] )

def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='Script to monitor mountpoint, indicate'
			' mount status and umount via tty commands to/from Arduino.')
	parser.add_argument('-m', '--mp', help='Mountpoint to monitor for status and run umount on.')
	parser.add_argument('-d', '--tty-dev',
		metavar='dev', default='/dev/ttyACM0',
		help='Terminal device used for communicating with an Arduino board. Default: %(default)s')
	parser.add_argument('-b', '--baud-rate', metavar='rate', default=115200,
		help='Baud rate for tty device communication. Default: %(default)s')
	parser.add_argument('-t', '--mount-recheck-interval',
		type=float, metavar='seconds', default=40,
		help='Interval between force-checking mountinfo'
			' status for mountpoint (poll timeout). Default: %(default)ss')
	parser.add_argument('-p', '--pid-file',
		metavar='file', help='File to write pid into, for signaling.')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global p
	if opts.debug: p = ft.partial(print, flush=True)

	with cl.ExitStack() as ctx:
		if pid := opts.pid_file and pl.Path(opts.pid_file):
			pid_file = ctx.enter_context(open(os.open(
				opts.pid_file, os.O_RDWR | os.O_CREAT, 0o600 ), 'r+b', 0))
			fcntl.lockf(pid_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
			pid_file.seek(0); pid_file.write(f'{os.getpid()}\n'.encode()); pid_file.truncate()
			ctx.callback(lambda: pid.unlink(missing_ok=True))

		dev = ctx.enter_context(serial.Serial(
			opts.tty_dev, opts.baud_rate, timeout=1.0, rtscts=True ))
		termios_hupcl_disable(dev.fd)
		task = run(dev, opts.mp.strip(), mount_recheck_interval=opts.mount_recheck_interval)
		try: return asyncio.run(task)
		except asyncio.CancelledError: pass

if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	sys.exit(main())
