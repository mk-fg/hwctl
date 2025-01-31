#!/usr/bin/env python

import os, sys, time, signal, json

class adict(dict):
	def __init__(self, *args, **kws):
		super().__init__(*args, **kws)
		self.__dict__ = self

err_fmt = lambda err: f'[{err.__class__.__name__}] {err}'


### Part 1/2 - Subprocess to only interact with nfc-reader and scrap afterwards
# Using pyscard modules in main process makes it difficult to cleanly
#  disconnect it from pcsc-lite, stop it easily mid-thread and cleanup other stuff.
# Hence this stub to run that in a subprocess.

def retries_within_timeout( tries, timeout,
		backoff_func=lambda e,n: ((e**n-1)/(e*5)), slack=1e-2 ):
	if tries <= 1 or timeout <= 0: return [0]
	if tries == 2: return [0, timeout / 2]
	a, b = 0, timeout
	while True:
		m = (a + b) / 2
		delays = list(backoff_func(m, n) for n in range(tries))
		error = sum(delays) - timeout
		if abs(error) < slack: return delays
		elif error > 0: b = m
		else: a = m

def main_reader():
	# https://github.com/LudovicRousseau/pyscard
	import smartcard.System as sc_sys, smartcard.CardRequest as sc_req
	import smartcard.Exceptions as sc_exc

	conf = adict(json.loads(sys.stdin.read()))
	out = lambda s: print(s, flush=True)
	log_debug, log_err = lambda s: out(f'\0{s}'), lambda s: out(f'\1{s}')
	ts_bump = lambda *a: conf.update(ts_done=time.monotonic() + conf.td)
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	signal.signal(signal.SIGHUP, ts_bump)
	ts_bump()

	readers_seen = set()
	for delay in retries_within_timeout(conf.td_warmup_checks, conf.td_warmup):
		if delay: time.sleep(delay)
		for rr in (reader := sc_sys.readers()):
			if (rn := rr.name) in readers_seen: continue
			log_debug(f'Detected reader [ {rn} ]'); readers_seen.add(rn)
		if conf.name: reader = list(rr for rr in reader if conf.name in rr.name)
		if len(reader) == 1: reader = reader[0]; break
	else:
		rm = ' matching' if conf.name else ''
		if not reader: err = f'No{rm} PCSC-lite readers available'
		elif len(reader) > 1:
			err = ' '.join(repr(rr.name) for rr in reader)
			err = f'More than one{rm} PCSC-lite reader: {err}'
		return log_err(err)
	log_debug(f'Using reader [ {reader.name} ]')
	c_new = False
	while True:
		td = min(conf.td, conf.ts_done - time.monotonic() + 1)
		if td < 0: log_debug('reader loop done'); break
		try:
			c_req = sc_req.CardRequest(
				readers=[reader], newcardonly=c_new, timeout=td )
			c_new, c_svc = True, c_req.waitforcard()
		except sc_exc.CardRequestTimeoutException: continue
		try:
			(conn := c_svc.connection).connect()
			data, sw1, sw2 = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
			conn.disconnect()
		except sc_exc.NoCardException: c_new = False # removed too quickly
		except sc_exc.SmartcardException as err: log_err(f'reader error: {err_fmt(err)}')
		else: out(bytes(data).hex()); ts_bump()

if __name__ == '__main__' and (
		len(sys.argv) > 1 and sys.argv[1] == '--nfc' ): sys.exit(main_reader())


### Part 2/2 - Main asyncio-loop process

import ctypes as ct, collections as cs, pathlib as pl, subprocess as sp
import re, logging, struct, fcntl, termios, errno, asyncio, configparser


_td_days = dict(
	y=365.2422, yr=365.2422, year=365.2422,
	mo=30.5, month=30.5, w=7, week=7, d=1, day=1 )
_td_s = dict( h=3600, hr=3600, hour=3600,
	m=60, min=60, minute=60, s=1, sec=1, second=1 )
_td_usort = lambda d: sorted(
	d.items(), key=lambda kv: (kv[1], len(kv[0])), reverse=True )
_td_re = re.compile('(?i)^[-+]?' + ''.join( fr'(?P<{k}>\d+{k}\s*)?'
	for k, v in [*_td_usort(_td_days), *_td_usort(_td_s)] ) + '$')

def td_parse(td_str):
	try: return float(td_str)
	except: td = 0
	if (m := _td_re.search(td_str)) and any(m.groups()):
		# Short time offset like "3d 5h"
		for n, units in enumerate((_td_days, _td_s)):
			tdx = 0
			for k, v in units.items():
				if not m.group(k): continue
				tdx += v * int(''.join(filter(str.isdigit, m.group(k))) or 1)
			td += (24*3600)**(1-n) * tdx
		return td
	if m := re.search(r'^\d{1,2}:\d{2}(?::\d{2}(?P<us>\.\d+)?)?$', td_str):
		# [[HH:]MM:]SS where seconds can be fractional
		return sum(n*float(m) for n,m in zip((3600, 60, 1), td_str.split(':')))
	raise ValueError(f'Failed to parse time-delta spec: {td_str}')


conf_defaults = adict(
	hwctl = adict(
		log_file = '',
		log_tail_bytes = 1024,
		log_time_slack = 30.0,
		log_oserr_retry = 0.05,
		fifo = '',
		fifo_enable_btns = '',
		fifo_disable = '' ),
	main = adict(
		reader_name = '',
		reader_warmup = 3.0,
		reader_warmup_checks = 10,
		reader_timeout = 3.0 * 60,
		exit_timeout = 0.0 ),
	actions = adict() ) # name = {uid, run, stdin, stop_timeout}

def conf_parse_ini(p):
	conf = adict((k, adict(c)) for k, c in conf_defaults.items())
	(parser := configparser.ConfigParser(
		default_section='', allow_no_value=True, interpolation=None )).read(p)
	ck_map = {'hwctl-reader-control': conf.hwctl, 'main': conf.main}
	pre, conf_warn = f'[conf {p.name}]', lambda: log.warning(
		'%s Unused config value: [%s] %s = %s', pre, ck, sk, sv )
	for ck, sec in parser.items():
		if c := ck_map.get(ck):
			for sk, sv in sec.items():
				if (v := c.get(k := sk.replace(*'-_'))) is None: conf_warn(); continue
				if isinstance(v, float): c[k] = td_parse(sv)
				else: c[k] = type(v)(sv)
		elif (m := re.match(r'action:\s+(.*)', ck)) and (ak := m[1]):
			act = conf.actions[ak] = adict(name=ak)
			for sk, sv in sec.items():
				if sk == 'uid': sv = ''.join(c for c in sv if c in '0123456789abcdefABCDEF').lower()
				elif sk == 'run': sv = list( # '...' - arg with spaces and ''-escapes
					s.replace('\uf43b', '').replace('\uea3a', ' ') for s in re.sub(
						r"'(.*?)'", lambda m: m[1].replace(' ', '\uea3a').replace('\uf43b', "'"),
						sv.replace("''", '\uf43b') ).split() )
				elif sk == 'stdin': sv = sv.strip()
				elif sk == 'stop-timeout': sv = td_parse(sv)
				else: conf_warn(); continue
				act[sk.replace(*'-_')] = sv
			if not (act.get('uid') and act.get('run')): log.warning(
				'%s Ignoring action section without uid/run values: [%s]', pre, ck )
		elif ck: log.warning('%s Unused config section: [%s]', pre, ck)
	if cmds := conf.hwctl.fifo_enable_btns.split():
		btn_map = conf.hwctl.fifo_enable_btns = dict()
		for spec in cmds:
			try:
				n, cmd = spec.split(':', 1)
				btn_map.setdefault(int(n), list()).append(cmd)
			except: log.warning('%s Incorrect fifo-enable-btns spec: %s', pre, spec)
	if cmds := conf.hwctl.fifo_disable.split(): conf.hwctl.fifo_disable = cmds
	return conf


class INotify:
	class flags: modify = 0x00000002 # see "man inotify"
	_libc, _INotifyEv = None, struct.Struct('iIII')
	INotifyEv = cs.namedtuple( 'INotifyEv',
		'path path_mask wd flags cookie name' )
	INotifyEvTracker = cs.namedtuple('INotifyCtl', 'add rm ev_iter')

	@classmethod
	def _get_lib(cls):
		if cls._libc is None: libc = cls._libc = ct.CDLL('libc.so.6', use_errno=True)
		return cls._libc
	def __init__(self): self._lib = self._get_lib()

	def _call(self, func, *args):
		if isinstance(func, str): func = getattr(self._lib, func)
		while True:
			res = func(*args)
			if res == -1:
				err = ct.get_errno()
				if err == errno.EINTR: continue
				else: raise OSError(err, os.strerror(err))
			return res

	def open(self):
		self.fd, self.wd_info = self._call('inotify_init'), dict() # (path, mask, queue)
		asyncio.get_running_loop().add_reader(self.fd, self.read)
		return self
	def close(self):
		for path, mask, queue in self.wd_info.values(): queue.put_nowait(None)
		asyncio.get_running_loop().remove_reader(self.fd)
		self.fd = self.wd_info = os.close(self.fd)
	async def __aenter__(self): return self.open()
	async def __aexit__(self, *err): self.close()

	def read(self):
		bs = ct.c_int(); fcntl.ioctl(self.fd, termios.FIONREAD, bs)
		if bs.value <= 0: return
		buff = os.read(self.fd, bs.value); n, bs = 0, len(buff)
		while n < bs:
			wd, flags, cookie, name_len = self._INotifyEv.unpack_from(buff, n)
			n += self._INotifyEv.size
			name = ct.c_buffer(buff[n:n + name_len], name_len).value.decode()
			n += name_len
			try:
				path, mask, queue = self.wd_info[wd]
				queue.put_nowait(self.INotifyEv(path, mask, wd, flags, cookie, name))
			except KeyError: pass # after rm_watch or IN_Q_OVERFLOW (wd=-1)
		if n != bs: log.warning(
			'Unused trailing bytes on inotify-fd [%s]: %s',
			(bs := bs - n), ct.c_buffer(buff[n:], bs).value )

	def get_ev_tracker(self):
		queue = asyncio.Queue()
		def add(path, mask):
			wd = self._call('inotify_add_watch', self.fd, bytes(path), mask)
			self.wd_info[wd] = path, mask, queue; return wd
		def rm(wd):
			if not self.fd: return
			self._call('inotify_rm_watch', self.fd, wd); self.wd_info.pop(wd)
		async def ev_iter(dummy_first=True, dummy_interval=None):
			if dummy_first: yield # for easy setup-on-first-iter in "async for"
			while True:
				ev = queue.get()
				if dummy_interval: ev = asyncio.wait_for(ev, dummy_interval)
				try: ev = await ev
				except asyncio.TimeoutError: ev = False
				if ev is None: break
				yield ev
		return self.INotifyEvTracker(add, rm, ev_iter)

async def run_log_tail(p, cb, tail_bytes=10*2**10, oserr_delay=0.05):
	'''Send lines from specified log-path to callback as soon as they appear there.
		Uses inotify on dir to detect changes, runs stat() inode-check before reads.'''
	(inotify := INotify()).open(); inn_fd = log_file = log_ino = None
	try:
		inn_fd = (inn := inotify.get_ev_tracker()).add(p.parent, inotify.flags.modify)
		async for ev in inn.ev_iter():
			if ev and ev.name != p.name: continue
			for n in range(4):
				try: ino = p.stat().st_ino; break
				except OSError: await asyncio.sleep(oserr_delay) # rotation/chmod
			else: continue
			if log_file and ino != log_ino:
				while line := log_file.readline(): cb(line.decode().strip())
				log_file = log_ino = log_file.close()
			if not log_file:
				for n in range(3):
					try: log_file = p.open('rb'); break
					except OSError as log_err: await asyncio.sleep(oserr_delay)
				else:
					log.warning('Failed to open log-file [ %s ]: %s', p, err_fmt(log_err))
					continue
				if tail_bytes:
					try:
						log_file.seek(-tail_bytes, os.SEEK_END)
						if log_file.tell() != 0: log_file.readline() # to next complete line
					except OSError: pass # smaller than tail_bytes
					tail_bytes = None # skip for new files
				log_ino = os.stat(log_file.fileno()).st_ino
			while line := log_file.readline(): cb(line.decode().strip())
	finally:
		if log_file: log_file.close()
		if inn_fd is not None: inn.rm(inn_fd)
		inotify.close()


async def run_proc(name, cmd, stdin, timeout, kill_delay=2.0):
	proc, pre = None, f'[action {name}]'
	try:
		async with asyncio.timeout(timeout or 2**32):
			proc = await asyncio.create_subprocess_exec(
				*cmd, stdin=sp.PIPE if stdin else None )
			if stdin: await proc.communicate(stdin.encode())
	except asyncio.CancelledError: pass
	except asyncio.TimeoutError: log.debug('%s Process timed out', pre)
	except Exception as err: log.error('%s Failed with error: %s', pre, err_fmt(err))
	if not proc: return
	if (n := proc.returncode) is not None:
		return log.debug('%s Process exited (code=%s)', pre, n)
	try:
		try:
			async with asyncio.timeout(kill_delay): proc.terminate(); await proc.wait()
		except asyncio.TimeoutError: proc.kill()
	except OSError: pass
	log.debug('%s Process terminated', pre)


async def run_reader(name, cb, proc_info, times, kill_delay=2.0):
	proc, pre, log_fns = None, f'[nfc]', dict(enumerate([log.debug, log.error]))
	try:
		proc = await asyncio.create_subprocess_exec(
			sys.executable or 'python', __file__, '--nfc', stdin=sp.PIPE, stdout=sp.PIPE )
		proc_info.pid = proc.pid
		proc.stdin.write(json.dumps(dict(name=name, **times)).encode())
		await proc.stdin.drain(); proc.stdin.close(); await proc.stdin.wait_closed()
		while (line := await proc.stdout.readline()):
			if not (log_fn := log_fns.get(line[0])): cb(line.decode().strip())
			else: log_fn('[nfc] ' + line[1:].decode().strip())
	except asyncio.CancelledError: pass
	except Exception as err: log.error('%s subproc failed: %s', pre, err_fmt(err))
	if not proc: return
	if (n := proc.returncode) is not None:
		return log.debug('%s subproc exited (code=%s)', pre, n)
	try:
		try:
			async with asyncio.timeout(kill_delay): proc.terminate(); await proc.wait()
		except asyncio.TimeoutError: proc.kill()
	except OSError: pass
	log.debug('%s subproc terminated', pre)


async def run(conf):
	tasks, evq, loop = set(), asyncio.Queue(), asyncio.get_running_loop()
	evq_task = exit_task = nfc_task = None
	task_done = lambda tt: not tt or tt.done()
	def task_new(**named_task):
		(name, coro), = named_task.items()
		tasks.add(tt := asyncio.create_task(coro, name=name)); return tt

	def exit_task_bump():
		nonlocal exit_task
		if not task_done(exit_task): exit_task.cancel(); exit_task = None
		if not task_done(nfc_task): return
		if any(tt.get_name() in ['act', 'fifo'] for tt in tasks): return
		if (td := conf.main.exit_timeout) > 0:
			log.debug('exit: scheduled in %ss', td)
			exit_task = task_new(exit=asyncio.sleep(td))

	async def fifo_send(p, cmds, timeout=2.0):
		log.debug('hwctl: fifo command(s) - %s', cmds)
		eof, buff = asyncio.Future(), ''.join(f'{c}\n' for c in cmds).encode()
		_log_err = lambda msg: log.error( 'hwctl: fifo %s [ %s ]',
			msg, repr(buff) if len(buff) > 20 else repr(buff[:17])[:-1] + '...' )
		def _send():
			nonlocal buff
			try:
				if (n := os.write(fd, buff)) <= 0: raise OSError
			except OSError: return eof.set_result(_log_err('write failed'))
			if not (buff := buff[n:]): eof.set_result(None)
		try: fd = os.open(p, os.O_WRONLY | os.O_NONBLOCK)
		except OSError as err:
			if err.errno not in [errno.ENXIO, errno.ENOENT]: raise
			log.error('hwctl: no fifo path/reader [ %s ]', p); return
		try:
			try: loop.add_writer(fd, _send)
			except OSError:
				log.debug('hwctl: fifo blocking write')
				while not eof.done(): _send()
			else:
				try:
					async with asyncio.timeout(timeout): await eof
				finally: loop.remove_writer(fd)
		except asyncio.TimeoutError: _log_err('write timeout')
		finally: os.close(fd)

	nfc_proc = adict()
	def nfc_start():
		nonlocal nfc_task
		if not task_done(nfc_task) and (pid := nfc_proc.get('pid')):
			try: return os.kill(pid, signal.SIGHUP)
			except OSError: return
		exit_task_bump()
		task_new(reader=run_reader(
			conf.main.reader_name, lambda ev: evq.put_nowait(dict(nfc=ev)),
			nfc_proc, times=adict( td=conf.main.reader_timeout,
				td_warmup=conf.main.reader_warmup,
				td_warmup_checks=conf.main.reader_warmup_checks )))
		log.debug('NFC: started reader subprocess')

	for sig in 'INT', 'TERM': loop.add_signal_handler(
		getattr(signal, f'SIG{sig}'), lambda _sig=sig: (
			log.debug('Exiting on signal %s', _sig), evq.put_nowait(None) ) )

	if conf.hwctl.log_file:
		task_new(btns_log=run_log_tail(
			pl.Path(conf.hwctl.log_file), lambda ev: evq.put_nowait(dict(btn=ev)),
			tail_bytes=conf.hwctl.log_tail_bytes, oserr_delay=conf.hwctl.log_oserr_retry ))
		exit_task_bump()
	else: nfc_start()

	running = True
	while running:
		if task_done(evq_task): evq_task = task_new(ev=evq.get())
		done, tasks = await asyncio.wait(
			tasks, return_when=asyncio.FIRST_COMPLETED )
		for tt in done:
			task = tt.get_name()
			try: ev = await tt
			except asyncio.CancelledError: continue
			log.debug('Loop: %s/%s %s', task, len(tasks), ev or '-')
			if task == 'exit': ev = None
			elif task == 'reader': ev = dict(nfc=StopIteration)
			elif task in ['act', 'fifo']: exit_task_bump(); continue
			elif task != 'ev': raise RuntimeError(f'Daemon task failed: {task}')
			if not ev: running = log.debug('Loop: exiting'); continue

			if line := ev.get('btn'):
				try: btn_ts, btn = line.split(None, 2); btn_ts, btn = (
					float(btn_ts), int((m := re.fullmatch(r'btn=(\d+)', btn)) and m[1] or 0) )
				except: log.debug('hwctl: unrecognized btn-log line [ %s ]', line); continue
				if time.time() - btn_ts > conf.hwctl.log_time_slack: continue
				if not (cmds := conf.hwctl.fifo_enable_btns.get(btn)): continue
				if conf.hwctl.fifo: task_new(fifo=fifo_send(conf.hwctl.fifo, cmds))
				nfc_start()

			elif nfc_uid := ev.get('nfc'):
				if nfc_uid is StopIteration:
					if cmds := conf.hwctl.fifo and conf.hwctl.fifo_disable:
						task_new(fifo=fifo_send(conf.hwctl.fifo, cmds))
					exit_task_bump(); continue
				nfc_uid, nfc_uid_found = nfc_uid.lower(), False
				for act in conf.actions.values():
					if act.uid != nfc_uid: continue
					task_new(act=run_proc( act.name,
						act.run, act.get('stdin'), act.get('stop_timeout') ))
					nfc_uid_found = True
				if not nfc_uid_found: log.debug('NFC: no action for UID - %s', nfc_uid)

	log.debug('Loop: finished')
	for tt in tasks:
		if task_done(tt): continue
		try: tt.cancel(); await tt
		except asyncio.CancelledError: pass


def main(args=None):
	import argparse, textwrap
	dd = lambda text: re.sub( r' \t+', ' ',
		textwrap.dedent(text).strip('\n') + '\n' ).replace('\t', '  ')
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawTextHelpFormatter, description=dd('''
			Script to run configured commands based on NFC sticker UIDs.
			Can interact with running hwctl.py script from the same repo
				to enable NFC reader via some button wired to GPIO pin,
				starting from e.g. systemd.path unit when its buttons log-file updates.'''))
	parser.add_argument('-c', '--conf', metavar='path',
		default=pl.Path(__file__).name.removesuffix('.py') + '.ini', help=dd('''
			Configuration file (INI format) with NFC reader and NFC-UID action commands.
			See nfc-sticker-actions.example.ini file in the repo next to
				this script for an example and a list of all supported options there.
			Default: %(default)s'''))
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	logging.basicConfig( level=logging.DEBUG if opts.debug else logging.WARNING,
		style='{', format='{levelname:5} :: {message}', datefmt='%Y-%m-%dT%H:%M:%S' )
	log = logging.getLogger('nsa')

	conf = conf_parse_ini(pl.Path(opts.conf))
	try: return asyncio.run(run(conf))
	except asyncio.CancelledError: pass

if __name__ == '__main__': sys.exit(main())
