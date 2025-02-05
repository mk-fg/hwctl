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


gifs = cs.namedtuple('GIFStage', 'b64 ox oy td')
tdr = cs.namedtuple('TimeDeltaRNG', 'chance time_min time_max')

def tdr_ms(delay):
	if isinstance(delay, (int, float)): return round(1000*delay)
	for tdr in delay:
		if random.random() > tdr.chance: continue
		return round(1000*( tdr.time_min +
			random.random() * (tdr.time_max - tdr.time_min) ))
	return 0

def run(gif_loop, td_ack, td_post, td_sleep, **gif_kws):
	c_ack, trails = (0, 20, 0), (1, 0.5, 0.2, 0.05)
	for n in range(npw + len(trails) - 1):
		np.fill(b'\0\0\0')
		ny, nx = min(nph, round(n * nph/npw)), n
		for o, k in reversed(list(enumerate(trails))):
			c = tuple(round(c*k) for c in c_ack)
			if npw > (n := nx-o) >= 0:
				for y in range(nph): np[y*npw + n] = c
			if nph > (n := ny-o) >= 0:
				for x in range(npw): np[n*npw + x] = c
		np.write(); time.sleep_ms(15)
	np.fill(b'\0\0\0'); np.write(); time.sleep_ms(tdr_ms(td_ack))

	gif_draw = draw_gif_anim(gif_loop.b64, ox=gif_loop.ox, oy=gif_loop.oy, **gif_kws)
	ts_deadline = time.ticks_ms() + tdr_ms(gif_loop.td)
	while time.ticks_diff(ts_deadline, time.ticks_ms()) > (td := tdr_ms(td_sleep)):
		time.sleep_ms(td); draw_border(b'\0\0\1')
		while True:
			ms, end = gif_draw()
			if ms: np.write(); time.sleep_ms(ms)
			if end: time.sleep_ms(tdr_ms(td_post)); break
		np.fill(b'\0\0\0'); np.write()

run(
	td_ack=[tdr(0.5, 2, 5), tdr(1, 4, 9)],
	gif_loop=gifs(gif_nyawn, ox=1, oy=3, td=3 * 60),
	td_post=[tdr(0.5, 1, 2), tdr(0.9, 1.5, 4), tdr(1, 3, 6)],
	td_sleep=[tdr(0.1, 0, 0), tdr(0.5, 6, 15), tdr(1, 8, 20)],
	rgb_dim=(0.5, 0.035, 0.007) )
