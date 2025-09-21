#!/usr/bin/env python

import os, sys, time, signal, json

class adict(dict):
	def __init__(self, *args, **kws):
		super().__init__(*args, **kws)
		self.__dict__ = self

err_fmt = lambda err: f'[{err.__class__.__name__}] {err}'


### Part 1/2 - Subprocess to only interact with nfc-reader and scrap afterwards
# pyscard module relies on python GC to disconnect from pcscd,
#  which is unreliable, and it's difficult to stop it cleanly in threads.
# Hence this stub to run that in a subprocess, where stop/cleanup is easy.
# See https://github.com/LudovicRousseau/pyscard/issues/223 for more details.

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
	c_new, (tbf_burst, tbf_rate) = False, conf.tbf_checks
	tbf_n, tbf_rate, ts = tbf_burst, tbf_rate**-1, time.monotonic()
	while True:
		if (tbf_n := min( tbf_burst, tbf_n - 1 # simple token-bucket rate-limiting
				+ tbf_rate * abs(ts - (ts := time.monotonic())) )) < 0:
			time.sleep((1 - tbf_n) / tbf_rate)
		if (td := min(conf.td, conf.ts_done - ts + 1)) < 0: log_debug('reader done'); break
		try:
			c_req = sc_req.CardRequest(
				readers=[reader], newcardonly=c_new, timeout=td )
			c_new, c_svc = True, c_req.waitforcard()
		except sc_exc.CardRequestTimeoutException: continue
		try:
			(conn := c_svc.connection).connect()
			data, *extras = conn.transmit(list(bytes.fromhex(conf.cmd)))
			getattr(conn, 'close', conn.disconnect)() # newer pyscard might have close()
		except sc_exc.NoCardException: c_new = False # removed too quickly
		except sc_exc.SmartcardException as err: log_err(f'reader error: {err_fmt(err)}')
		else: out(bytes(data).hex()); ts_bump()

if __name__ == '__main__' and (
		len(sys.argv) > 1 and sys.argv[1] == '--nfc' ): sys.exit(main_reader())


### Part 2/2 - Main asyncio-loop process

import ctypes as ct, collections as cs, contextlib as cl, pathlib as pl, subprocess as sp
import re, logging, logging.handlers, struct, fcntl, termios, errno, asyncio, configparser


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
		debug = False,
		debug_log_file = '',
		debug_log_default_bs = '100K',
		debug_log_default_n = 3,
		reader_name = '',
		reader_uid_cmd = '',
		reader_warmup = 3.0,
		reader_warmup_checks = 10,
		reader_timeout = 3.0 * 60,
		exit_timeout = 0.0 ),
	actions = adict() ) # name = { uid (required), pre_hwctl,
	#  pre_wait, pre_wait_timeout, run, stdin, stop_timeout, stop_hwctl }

def conf_parse_ini(p):
	conf = adict((k, adict(c)) for k, c in conf_defaults.items())
	(parser := configparser.ConfigParser(
		default_section='', allow_no_value=True, interpolation=None )).read(p)
	pre, conf_warn = f'[conf {p.name}]', lambda: log.warning(
		'%s Unused config value: [%s] %s = %s', pre, ck, sk, sv )
	for ck, sec in parser.items():
		if c := conf.get(ck):
			for sk, sv in sec.items():
				if (v := c.get(k := sk.replace(*'-_'))) is None: conf_warn(); continue
				if isinstance(v, float): c[k] = td_parse(sv)
				else: c[k] = type(v)(sv)
		elif (m := re.match(r'action:\s+(.*)', ck)) and (ak := m[1]):
			act = conf.actions[ak] = adict(name=ak)
			for sk, sv in sec.items():
				if (sk := sk.replace(*'_-')) == 'stdin': sv = sv.strip()
				elif sk == 'uid': sv = ''.join(c for c in sv.lower() if c in '0123456789abcdef')
				elif sk == 'btn': sv = list(int(n) for n in sv.split())
				elif sk == 'run': sv = list( # '...' - arg with spaces and ''-escapes
					s.replace('\uf43b', '').replace('\uea3a', ' ') for s in re.sub(
						r"'(.*?)'", lambda m: m[1].translate({32:'\uea3a', 10:None, 0xf43b:"'"}),
						sv.replace("''", '\uf43b'), flags=re.DOTALL ).split() )
				elif sk in ['pre-wait-timeout', 'stop-timeout']: sv = td_parse(sv)
				elif sk in ['pre-hwctl', 'stop-hwctl']: sv = sv.split()
				elif sk == 'pre-wait' and (svx := sv.split()):
					sv = list(v for v in svx if re.fullmatch(r'path:.*', v))
					if len(sv) != len(svx): log.warning(
						'%s Ignoring unrecognized pre-wait specs: [%s] %s',
						pre, ck, ' '.join(v for v in sv if v not in svx) )
				else: conf_warn(); continue
				act[sk.replace(*'-_')] = sv
			if not (act.get('uid') or act.get('btn')): log.warning(
				'%s Ignoring action section without uid= or btn= values: [%s]', pre, ck )
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
	class flags: modify = 0x02; new = modify | 0x20 | 0x80 | 0x0100
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
			with cl.suppress(KeyError): # after rm_watch or IN_Q_OVERFLOW (wd=-1)
				path, mask, queue = self.wd_info[wd]
				queue.put_nowait(self.INotifyEv(path, mask, wd, flags, cookie, name))
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

async def run_log_tail(inotify, p, cb, tail_bytes=10*2**10, oserr_delay=0.05):
	'''Send lines from specified log-path to callback as soon as they appear there.
		Uses inotify on dir to detect changes, runs stat() inode-check before reads.'''
	inn_fd = log_file = log_ino = None
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
					with cl.suppress(OSError): # file < tail_bytes
						log_file.seek(-tail_bytes, os.SEEK_END)
						if log_file.tell() != 0: log_file.readline() # to next complete line
					tail_bytes = None # skip for new files
				log_ino = os.stat(log_file.fileno()).st_ino
			while line := log_file.readline(): cb(line.decode().strip())
	finally:
		if log_file: log_file.close()
		if inn_fd is not None: inn.rm(inn_fd)


async def run_fifo_send(p, cmds, timeout=2.0):
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
		try: (loop := asyncio.get_running_loop()).add_writer(fd, _send)
		except OSError:
			log.debug('hwctl: fifo blocking write')
			while not eof.done(): _send()
		else:
			try:
				async with asyncio.timeout(timeout): await eof
			finally: loop.remove_writer(fd)
	except asyncio.TimeoutError: _log_err('write timeout')
	finally: os.close(fd)


async def run_proc_cleanup(proc, log_prefix, kill_delay=2.0):
	if not proc: return
	log_fn = lambda msg,*a: log.debug(f'%s {msg}', log_prefix, *a)
	if (n := proc.returncode) is not None: return log_fn('exited (code=%s)', n)
	try:
		with cl.suppress(OSError): proc.terminate()
		async with asyncio.timeout(kill_delay): await proc.wait()
	except asyncio.TimeoutError: pass
	finally:
		if not (term := proc.returncode is not None):
			with cl.suppress(OSError): term = proc.kill()
		log_fn('terminated' if term else 'killed')

async def run_proc_action(name, cmd, stdin):
	proc, pre = None, f'[action {name}]'
	try:
		proc = await asyncio.create_subprocess_exec(
			*cmd, stdin=sp.PIPE if stdin else None )
		log.debug('%s Process started', pre)
		await proc.communicate(stdin.encode() if stdin else None)
	except Exception as err: log.error('%s Failed with error: %s', pre, err_fmt(err))
	finally: await run_proc_cleanup(proc, f'{pre} Process')

async def run_proc_reader(name, cb, proc_info, uid_cmd, times):
	proc, pre, log_fns = None, f'[nfc]', dict(enumerate([log.debug, log.error]))
	try:
		proc = await asyncio.create_subprocess_exec(
			sys.executable or 'python', __file__, '--nfc', stdin=sp.PIPE, stdout=sp.PIPE )
		proc_info.pid = proc.pid
		proc.stdin.write(json.dumps(dict(name=name, cmd=uid_cmd, **times)).encode())
		await proc.stdin.drain(); proc.stdin.close(); await proc.stdin.wait_closed()
		while (line := await proc.stdout.readline()):
			if not (log_fn := log_fns.get(line[0])): cb(line.decode().strip())
			else: log_fn('[nfc] ' + line[1:].decode().strip())
	except Exception as err: log.error('%s subproc failed: %s', pre, err_fmt(err))
	finally: await run_proc_cleanup(proc, f'{pre} subproc')


async def run(conf):
	evq, loop = asyncio.Queue(), asyncio.get_running_loop()
	tasks, tasks_cancel = set(), set()
	task_done = lambda tt: not tt or tt.done()
	def task_new(**named_task):
		(name, coro), = named_task.items()
		tasks.add(tt := asyncio.create_task(coro, name=name)); return tt
	task_cancel = lambda tt: tasks_cancel.add(tt) or tt.cancel()

	def fifo_send(cmds, timeout=2.0):
		if not cmds: return
		if not (p := conf.hwctl.fifo):
			return log.debug('hwctl: fifo disabled, ignoring commands [ %r ]', cmds)
		task_new(fifo=run_fifo_send(p, cmds))

	nfc_task, nfc_task_proc = None, adict()
	def nfc_start():
		nonlocal nfc_task, nfc_task_proc
		if not task_done(nfc_task) and (pid := nfc_task_proc.get('pid')):
			try: return os.kill(pid, signal.SIGHUP)
			except OSError: return

		nfc_task = task_new(reader=run_proc_reader(
			conf.main.reader_name, lambda ev: evq.put_nowait(dict(nfc=ev)),
			nfc_task_proc := adict(), uid_cmd=conf.main.reader_uid_cmd, times=adict(
				td=conf.main.reader_timeout, td_warmup=conf.main.reader_warmup,
				tbf_checks=(4, 1.0), td_warmup_checks=conf.main.reader_warmup_checks )))
		log.debug('NFC: started reader subprocess')
		exit_task_update()

	exit_task = exit_task_ts = None
	def exit_task_update():
		nonlocal exit_task, exit_task_ts
		if not task_done(nfc_task) or any(
				tt.get_name() in ['act_run', 'act_stop', 'fifo'] for tt in tasks ):
			if exit_task_ts: log.debug('exit: cancelled')
			exit_task_ts = None; return
		if (td := conf.main.exit_timeout) <= 0: return
		if exit_task_ts:
			if (td := exit_task_ts - time.monotonic()) <= 0: return evq.put_nowait(None)
		else: exit_task_ts = time.monotonic() + td; log.debug('exit: scheduled in %ss', td)
		if task_done(exit_task): exit_task = task_new(exit=asyncio.sleep(td))

	async def act_run_wait(name, act_func, waits, timeout):
		p_chk, inn, pre = dict(), None, f'[action {name}] pre-run'
		for s in waits or list():
			if not inn: inn = inotify.get_ev_tracker()
			if not (m := re.match(r'path:(.*)', s)): continue
			pp = (p := pl.Path(m[1])).parent.resolve(True)
			p_chk[wd := inn.add(pp, inotify.flags.new)] = p
		if not p_chk: return await act_func()
		try:
			log.debug('%s wait', pre)
			async with asyncio.timeout(timeout):
				async for ev in inn.ev_iter():
					if not ev: ev = list(p_chk.items())
					elif (p := p_chk.get(ev.wd)) and p.name == ev.name: ev = [(ev.wd, p)]
					else: continue
					for wd, p in ev:
						if not p.exists(): continue
						log.debug('%s path found [ %s ]', pre, p)
						inn.rm(wd); del p_chk[wd]
					if not p_chk: break
		except asyncio.TimeoutError:
			return log.debug('%s wait timeout, action cancelled', pre)
		finally:
			for wd in p_chk: inn.rm(wd)
		await act_func()

	async def act_timeout(name, act_task, timeout, cmds):
		pre = f'[action {name}]'
		if timeout: await asyncio.sleep(timeout)
		if not task_done(act_task):
			if not timeout: await act_task
			else: log.debug('%s stop-timeout for process', pre); task_cancel(act_task)
		if cmds: log.debug('%s stop commands', pre); fifo_send(cmds)

	(inotify := INotify()).open()
	for sig in 'INT', 'TERM': loop.add_signal_handler(
		getattr(signal, f'SIG{sig}'), lambda _sig=sig: (
			log.debug('Exiting on signal %s', _sig), evq.put_nowait(None) ) )

	if conf.hwctl.log_file:
		task_new(btns_log=run_log_tail( inotify,
			pl.Path(conf.hwctl.log_file), lambda ev: evq.put_nowait(dict(btn=ev)),
			tail_bytes=conf.hwctl.log_tail_bytes, oserr_delay=conf.hwctl.log_oserr_retry ))
		exit_task_update()
	else: nfc_start()

	running, evq_task = True, None
	while running:
		if task_done(evq_task): evq_task = task_new(ev=evq.get())
		done, tasks = await asyncio.wait(
			tasks, return_when=asyncio.FIRST_COMPLETED )
		for tt in done:
			task = tt.get_name()
			try: ev = await tt
			except asyncio.CancelledError:
				if tt not in tasks_cancel: raise
				ev = tasks_cancel.remove(tt)
			log.debug('Loop: %s/%s %s', task, len(tasks), ev or '-')
			if task == 'reader': ev = dict(nfc_done=True)
			elif task in ['act_run', 'act_stop', 'fifo', 'exit']: exit_task_update(); continue
			elif task != 'ev': raise RuntimeError(f'Daemon task failed: {task}')
			if not ev: running = log.debug('Loop: exiting'); continue

			if line := ev.get('btn'):
				try: btn_ts, btn = line.split(None, 2); btn_ts, btn = (
					float(btn_ts), int((m := re.fullmatch(r'btn=(\d+)', btn)) and m[1] or 0) )
				except: log.debug('hwctl: unrecognized btn-log line [ %s ]', line); continue
				if time.time() - btn_ts > conf.hwctl.log_time_slack: continue
				if cmds := conf.hwctl.fifo_enable_btns.get(btn): fifo_send(cmds); nfc_start()
				act_id = f'={btn}'
			elif ev.get('nfc_done'):
				fifo_send(conf.hwctl.fifo_disable); exit_task_update(); continue
			elif not (act_id := ev.get('nfc')): continue

			act_id = act_id.lower() if (act_nfc := act_id[0] != '=') else int(act_id[1:])
			act_found, log_id = False, f'NFC UID {act_id}' if act_nfc else f'button {act_id}'
			log.debug('action: lookup for %s', log_id)
			for act in conf.actions.values():
				if not (act_id == act.get('uid') or act_id in act.get('btn', list())): continue
				act_found = True
				if not task_done(act.get('task_run')):
					log.info('action: [%s] still running for %s', act.name, log_id)
					continue
				if run := act.get('run'):
					fifo_send(act.get('pre_hwctl'))
					act_run = lambda a=act: run_proc_action(a.name, a.run, a.get('stdin'))
					act_run = ( act_run() if not (pre_wait := act.get('pre_wait'))
						else act_run_wait(act.name, act_run, pre_wait, act.get('pre_wait_timeout')) )
					act.task_run = task_new(act_run=act_run)
				if not task_done(tt := act.get('task_stop')): task_cancel(tt)
				timeout, cmds = act.get('stop_timeout'), act.get('stop_hwctl')
				if timeout or cmds: act.task_stop = task_new(
					act_stop=act_timeout(act.name, act.get('task_run'), timeout, cmds) )
			if act_nfc and not act_found: log.warning('action: no match for %s', log_id)

	log.debug('Loop: finished')
	for tt in tasks:
		if task_done(tt): continue
		with cl.suppress(asyncio.CancelledError): tt.cancel(); await tt
	inotify.close()


def main_debug_log_setup(stderr, dst, dst_bs, dst_n):
	# Assumes logging.basicConfig initialized root logger/handler already
	if stderr: logging.root.setLevel(logging.DEBUG)
	else:
		for handler in logging.root.handlers: handler.setLevel(logging.WARNING)
	if not dst: return

	def _size_parse(size):
		if not size or not isinstance(size, str): return size
		if size[-1].isdigit(): return float(size)
		for u, u1 in reversed(list((u, 2 ** (n * 10)) for n, u in enumerate('BKMGT'))):
			if size[-1] == u: break
		else: raise ValueError('Unrecognized units: {} (value: {!r})'.format(size[-1], size))
		return float(size[:-1]) * u1

	if ':' in dst:
		dst, dst_bs = dst.split(':', 1)
		if ':' in dst_bs: dst_bs, dst_n = dst_bs.split(':', 1)
	dst_bs, dst_n = _size_parse(dst_bs), int(dst_n)

	handler = None
	if dst == '-': handler = logging.StreamHandler(sys.stdout)
	elif dst.startswith('%') and (fd := dst[1:]).isdigit():
		handler = logging.StreamHandler(open(int(fd), 'a'))
	elif (p := pl.Path(dst)).exists() and not p.is_file():
		handler = logging.FileHandler(dst)
	elif p.exists() and p.is_symlink(): p = p.resolve(True)
	if not handler:
		try:
			with p.open('a') as dst: dst.tell()
		except io.UnsupportedOperation:
			log.warning( 'Specified log file path is'
				' not seekable, disabling rotation: %s', p )
			handler = logging.FileHandler(p)
		else: handler = logging.handlers\
			.RotatingFileHandler(p, maxBytes=dst_bs, backupCount=dst_n)

	handler.setLevel(logging.DEBUG)
	handler.setFormatter(logging.Formatter(
		'{asctime} :: {levelname} :: {message}', style='{' ))
	log.addHandler(handler); log.setLevel(logging.DEBUG)

def main(args=None):
	log_bs, log_n = (conf_defaults.main[f'debug_log_default_{k}'] for k in ['bs', 'n'])

	import argparse, textwrap
	dd = lambda text: re.sub( r' \t+', ' ',
		textwrap.dedent(text).strip('\n') + '\n' ).replace('\t', '  ')
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawTextHelpFormatter, description=dd('''
			Script to run configured commands based on NFC sticker UIDs.
			Can interact with running hwctl.py script from the same repo to
				enable NFC reader via some button wired to GPIO pin or run actions on those,
				starting from e.g. systemd.path unit when its buttons log-file updates.'''))
	parser.add_argument('-c', '--conf', metavar='path',
		default=pl.Path(__file__).name.removesuffix('.py') + '.ini', help=dd('''
			Configuration file (INI format) with NFC reader and NFC-UID action commands.
			See nfc-sticker-actions.example.ini file in the repo next to
				this script for an example and a list of all supported options there.
			Default: %(default)s'''))
	parser.add_argument('--debug',
		action='store_true', help='Enable debug logging to stderr.')
	parser.add_argument('--debug-log-file',
		metavar=f'log-file[:bytes={log_bs}[:backups={log_n}]]', help=dd(f'''
			Enable debug output to an auto-rotated log file,
				with optional [:bytes[:backups]] suffix (default :{log_bs}:{log_n}).
			Can be e.g. %%3 to output to file descriptor 3, or '-' for stdout (default).
			Log won't be rotated if dev, fd or non-seekable, resolved to realpath if symlink.'''))
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	logging.basicConfig( level=logging.DEBUG if opts.debug else logging.WARNING,
		style='{', format='{levelname:5} :: {message}', datefmt='%Y-%m-%dT%H:%M:%S' )
	log = logging.getLogger('nsa')

	conf = conf_parse_ini(p := pl.Path(opts.conf))
	main_debug_log_setup(
		opts.debug or conf.main.debug,
		opts.debug_log_file or conf.main.debug_log_file,
		conf.main.debug_log_default_bs, conf.main.debug_log_default_n )
	if not conf.hwctl.log_file:
		if conf.hwctl.fifo_enable_btns:
			parser.error( f'[conf {p.name}] hwctl.fifo-enable-btns'
				' are specified without hwctl.log-file to read those from' )
		for name, act in conf.actions.items():
			if act.get('btn'): parser.error( f'[conf {p.name}] [action: {name}]'
				' has btn= trigger(s) set, with no hwctl.log-file to read those from' )
	try:
		if not (cmd := conf.main.reader_uid_cmd).strip(): raise ValueError
		bytes.fromhex(conf.main.reader_uid_cmd)
	except:
		parser.error(f'[conf {p.name}] main.reader-uid-cmd is missing or cannot be hex-decoded')

	with cl.suppress(asyncio.CancelledError): return asyncio.run(run(conf))

if __name__ == '__main__': sys.exit(main())
