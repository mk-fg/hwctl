# RP2040 micropython fw script to play animations on ws2812 neopixel RGB-LED panel

import random, collections as cs
import io, deflate, binascii, math, neopixel, machine, time


# 16x8 px, 49 frames, 11,490 ms total
gif_nyawn = '''
	eNoT4DBRUDL79NvIaI1rXjQDA4MRELOYJDiwsKg0XGA8wKIy4QLjBTeRDSUMpcpAK
	REwSxDICgCzOEQ2AkkThpIA4U0CDCIQNieY/YXhqwnDF4j4FYarIgxXmJHEIew/DH
	9tGP5A2DUM9TYMNRD1MQzxMgwxLEjiMHYtXA3ELmahzXA2ELEIbgNyDRhMICIMEKD
	AABRHFwQCDRziKxDiIgwhcEOQxRGKkcRdGAqRDQGJKy47wHDBgUEAJsrVwKAFJBWn
	HWD4ABMDCTEtYBDBEORagSG4qgEoWOHqpKW1agUXNjl2bKawY7MPh9twegWv1/EEF
	a6gxYwK7FEntAkuyCoEinkTMJdVeCMk5lPAKZEPnFK5VBoOMByoAGoEAIMEiwY='''

def parse_gif(b64_zlib_data):
	gif = io.BytesIO(binascii.a2b_base64(b64_zlib_data))
	with deflate.DeflateIO(gif, deflate.ZLIB) as gif:
		(w, h), pal, frames = gif.read(2), list(), list()
		while any(c := gif.read(3)): pal.append(c)
		cb_pack = (cb := math.ceil(math.log2(cn := len(pal)))) < 5
		while ms := gif.read(1):
			ms = ms[0] * 10; fxy, fwh = gif.read(2)
			fx, fy = fxy>>4, fxy & 0xf; fw, fh = (fwh>>4) + 1, (fwh & 0xf) + 1
			if not cb_pack: frame = gif.read(fw*fh)
			else:
				v = o = 0; m = 2**cb-1; frame = bytearray(fw*fh)
				for n in range(fw*fh):
					if o < cb: v = v << 8 | gif.read(1)[0]; o += 8
					o -= cb; frame[n] = v >> o; v &= 2**o-1; n += 1
			if fw == fh == 1 and not v: fw = fh = 0; frame = b''
			frames.append((ms, fx, fy, fw, fh, frame))
	return w, h, pal, frames


np = neopixel.NeoPixel(machine.Pin(6), 160)
npw, nph = 16, 10

def draw_border(c):
	for x in range(npw): np[0+x] = np[(nph-1)*npw+x] = c
	for y in range(nph): np[y*npw] = np[y*npw+npw-1] = c

def draw_gif_anim( gif_b64, ox=0, oy=0,
		rgb_dim=(0.5, 0.035, 0.007), bg=b'\0\0\0' ):
	w, h, pal, frames = parse_gif(gif_b64)
	npx, fn, fm = list(), 0, len(frames)
	def _draw():
		nonlocal fn
		ms, fx, fy, fw, fh, frame = frames[fn]
		if loop := (fn := fn + 1) == fm: fn = 0
		for o in npx: np[o] = bg
		npx.clear()
		if not fw: return ms, loop
		n, dx = 0, npw + ox
		for y in range(fy, fy+fh):
			dy = (nph - (oy+y)) * npw
			for o in range(dy+dx+fx, dy+dx+fx+fw):
				c = frame[n]; n += 1
				if not c: continue
				r, g, b = (round(c*k) for c, k in zip(pal[c], rgb_dim))
				npx.append(o); np[o] = g, r, b # color order for this panel
		return ms, loop
	return _draw


gifs = cs.namedtuple('GIFStage', 'b64 ox oy rgb_border td_loop')
acks = cs.namedtuple('ACKStage', 'rgb td trails')
tdr = cs.namedtuple('TimeDeltaRNG', 'chance td_min td_max')

def tdr_ms(delay):
	if isinstance(delay, (int, float)): return round(1000*delay)
	for tdr in delay:
		if random.random() > tdr.chance: continue
		return round(1000*( tdr.td_min +
			random.random() * (tdr.td_max - tdr.td_min) ))
	return 0

def run( gif, td_total, td_sleep, td_ackx=0, td_gifx=0,
		ack=acks(b'\0\x14\0', 0.24, (1, 0.5, 0.2, 0.05)), **gif_kws ):
	if not isinstance(gif, gifs): gif = gifs(*gif)
	if not isinstance(ack, acks): ack = acks(*ack)

	# Initial quick "ACK" animation, to indicate loop start
	dx, dy = random.random() > 0.5, random.random() > 0.5
	td_ack_iter, trails = round(tdr_ms(ack.td) / npw), ack.trails or [1]
	for n in range(npw + len(trails) - 1):
		np.fill(b'\0\0\0')
		fx, fy = ( ( (lambda o,_nk=nk: _nk - o)
				if d else (lambda n,_m=m,_nk=nk: _m - 1 - (_nk-o)) )
			for d, nk, m in [(dx, n, npw), (dy, min(nph, round(n * nph/npw)), nph)] )
		for o, k in reversed(list(enumerate(trails))):
			c = tuple(round(c*k) for c in ack.rgb)
			if npw > (n := fx(o)) >= 0:
				for y in range(nph): np[y*npw + n] = c
			if nph > (n := fy(o)) >= 0:
				for x in range(npw): np[n*npw + x] = c
		np.write(); time.sleep_ms(td_ack_iter)
	np.fill(b'\0\0\0'); np.write(); time.sleep_ms(tdr_ms(td_ackx))

	# Repeated gif animations with td_sleep interval, until td_total expires
	gif_draw = draw_gif_anim(gif.b64, ox=gif.ox, oy=gif.oy, **gif_kws)
	tsd_total = time.ticks_add(time.ticks_ms(), tdr_ms(td_total))
	while time.ticks_diff(tsd_total, time.ticks_ms()) > (td := tdr_ms(td_sleep)):
		time.sleep_ms(td)
		if gif.rgb_border: draw_border(gif.rgb_border)
		tsd_gif = gif.td_loop and time.ticks_add(time.ticks_ms(), tdr_ms(gif.td_loop))
		while not tsd_gif or time.ticks_diff(tsd_gif, time.ticks_ms()) > 0:
			ms, end = gif_draw()
			if ms: np.write(); time.sleep_ms(ms)
			if end and not tsd_gif: break # no looping
		time.sleep_ms(tdr_ms(td_gifx))
		np.fill(b'\0\0\0'); np.write()

def run_with_times( td_total=3 * 60, # total time before exiting
		td_sleep=[tdr(0.1, 0, 0), tdr(0.5, 6, 15), tdr(1, 8, 20)], # in disabled state b/w gifs
		td_ackx=[tdr(0.5, 0, 0), tdr(0.5, 2, 5), tdr(1, 4, 9)], # after ack animation
		td_gifx=[tdr(0.5, 0, 2), tdr(0.8, 1.5, 4), tdr(1, 3, 6)], **kws ): # after gif w/ decorations
	# td's here can be lists-of-tuples to auto-convert into tdr tuples
	td_make = lambda td: ( td if isinstance(td, (int, float))
		else list((tdt if isinstance(tdt, tdr) else tdr(*tdt)) for tdt in td) )
	kws = dict(dict(rgb_dim=(0.7, 0.02, 0.003)), **kws)
	run( gifs(gif_nyawn, ox=1, oy=3, rgb_border=b'\0\0\1', td_loop=None),
		td_make(td_total), td_make(td_sleep), td_make(td_ackx), td_make(td_gifx), **kws )

def run_clear(): np.fill(b'\0\0\0'); np.write() # to clear leds from mpremote

if __name__ == '__main__': run_with_times()
