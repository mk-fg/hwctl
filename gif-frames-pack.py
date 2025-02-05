#!/usr/bin/env python3

import itertools as it, subprocess as sp
import os, sys, io, re, math, struct, zlib, base64

from PIL import Image # https://pillow.readthedocs.io/


p = lambda *a,**kw: print(*a, **kw, flush=True)
p_err = lambda *a,**kw: print(*a, **kw, file=sys.stderr, flush=True) or 1

class adict(dict):
	def __init__(self, *args, **kws):
		super().__init__(*args, **kws)
		self.__dict__ = self

def get_frames(p):
	# https://www.piskelapp.com/p/create/sprite also saves spritesheets into same C arrays
	# Uses "magick" CLI tool from https://imagemagick.org/ to parse GIF per-frame delays
	frames, frame_delays = list(), list(map(int, sp.run([ 'magick', p,
		'-format', '%T0 ', 'info:' ], check=True, stdout=sp.PIPE).stdout.decode().split()))
	with Image.open(p) as img:
		img_checks = dict( anim=img.is_animated, alpha=img.has_transparency_data,
			palette=img.mode == 'P', palette_rgb=img.palette and img.palette.mode == 'RGB' )
		assert all(img_checks.values()), img_checks
		w, h, pal = img.width, img.height, img.palette
		for n in range(img.n_frames):
			img.seek(n); px = img.load(); frames.append(frame := list())
			for y, x in it.product(range(h), range(w)):
				if isinstance(p := px[x, y], int): frame.append(0) # all-bg first frame?
				else: r, g, b, a = px[x, y]; frame.append((b<<16) + (g<<8) + r)
	assert len(frames) == len(frame_delays), [len(frames), len(frame_delays)]
	return adict(w=w, h=h, frames=frames, delays=frame_delays)

def frame_crop(frame, w, h):
	fx, fy, fw, fh = 0, 0, w, h
	for row in frame:
		if any(row): break
		fy += 1; fh -= 1
	if not fh: return 0, 0, 0, 0
	for row in reversed(frame):
		if any(row): break
		fh -= 1
	frame = list(zip(*frame))
	for col in frame:
		if any(col): break
		fx += 1; fw -= 1
	for col in reversed(frame):
		if any(col): break
		fw -= 1
	return fx, fy, fw, fh


def main(args=None):
	import argparse, textwrap
	dd = lambda text: re.sub( r' \t+', ' ',
		textwrap.dedent(text).strip('\n') + '\n' ).replace('\t', '  ')
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawTextHelpFormatter,
		usage='%(prog)s [options] image.gif [image.npx]', description=dd('''
			Convert GIF image pixels to a simpler packed format,
				for easy embedding into scripts to display on neopixel led matrices.
			If output argument is not specified, dumps base64-encoded output to stdout.
			Only handles small images up to 16x16 size, due to using 4-bit dimensions.

			Output format outline: zlib( width <u8>, height <u8>,
				palette = { R <u8>, G <u8>, B <u8> [, palette ] }, 0 0 0,
				frames = { delay ms/10 <u8>, fx <u4>, fy <u4>,
					fw-1 <u4>, fh-1 <u4>, color x=fx y=fy <palette-bits>,
					color x=fx+1 y=fy, ..., color x=fx+fw y=fy+fh, ... [byte-pad] [, frames ] })
			Where <palette-bits> for each color is an uint with min bits needed to fit palette.
				For example with <=4 colors that'd be u2, u3 for up to 8 colors, an so on.
			fx/fy, fw/fh - x/y offset and width/height for pixels in that frame.'''))
	parser.add_argument('src', help='GIF image file to convert.')
	parser.add_argument('dst', nargs='?', help='Output file name for packed pixel data.')
	parser.add_argument('-b', '--bg-color', metavar='hex', help=dd('''
		Hex-encoded background/dominant color to strip on exact pixel match.
		Default - auto-detected as most common color among all pixels.'''))
	parser.add_argument('-q', '--quiet', action='store_true', help=dd('''
		Don't print information about input/output sizes and compression to stderr.'''))
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	p_info = p_err if not opts.quiet else lambda *a,**kw: None
	p_info(f'Source file [ {opts.src} ]: {os.stat(opts.src).st_size:,d} B')
	img = get_frames(opts.src)
	if bgc := opts.bg_color:
		if len(bgc) == 3: bgc = ''.join(bgc[n]*2 for n in range(3))
		if not bgc.startswith('0x'): bgc = f'0x{bgc}'
		bgc = int(bgc, 16)

	pal, cc = set(), dict()
	for frame in img.frames:
		for n, c in enumerate(frame):
			if not c: continue # = whatever background is
			c = frame[n] = c & 0xffffff # strip A from ABGR, if any
			pal.add(c); cc.setdefault(c, 0); cc[c] += 1
	assert len(pal) <= 256, len(pal)
	if not bgc: bgc = sorted((v, k) for k,v in cc.items())[-1][1]
	pal.discard(0) # black is never used as color for leds
	pal = dict((c, n) for n, c in enumerate(sorted(pal, key=lambda c: c != bgc)))

	w, h, nf = img.w, img.h, len(img.frames)
	cb_pack = (cb := math.ceil(math.log2(cn := len(pal)))) < 5
	p_info(f'GIF frames = {nf}, total duration = {sum(img.delays):,d} ms')
	p_info(f'Palette colors = {cn}, color-bits = {cb}, bg = {bgc:x}, pack bits = {cb_pack}')

	frames_enc = list()
	for ms, frame in zip(img.delays, img.frames):
		assert (msb := ms // 10) == ms/10 and msb < 256, ms
		frame = list(list(c and pal[c] for c in cc) for cc in it.batched(frame, n=w))
		fx, fy, fw, fh = frame_crop(frame, w, h)
		if not fw: frames_enc.append([msb, 0, 0, 0]); continue
		buff = [msb, (fx<<4) + fy, ((fw-1)<<4) + fh-1]
		if not cb_pack:
			for row in frame[fy:fy+fh]:
				for c in row[fx:fx+fw]: buff.append(c)
		else:
			fn = fb = 0
			for row in frame[fy:fy+fh]:
				for c in row[fx:fx+fw]:
					fn = (fn << cb) | c; fb += cb
					if (n := fb - 8) >= 0: buff.append(fn >> n); fn &= 2**n-1; fb -= 8
			if fb: buff.append(fn << 8-fb)
		frames_enc.append(buff)
	assert len(frames_enc) == nf, [len(frames_enc), nf]

	with io.BytesIO() as dst:
		dst.write(struct.pack('BB', w, h))
		for c, n in sorted(pal.items(), key=lambda cn: cn[1]):
			dst.write((c & 0xffffff).to_bytes(3, 'big'))
		dst.write(b'\0\0\0')
		for buff in frames_enc: dst.write(bytes(buff))
		data = zlib.compress(dst.getvalue(), level=9, wbits=15)

	p_info(f'Output file [ {opts.dst or "-"} ]: {len(data):,d} B (zlib level=9 wbits=15)')
	if not opts.dst:
		splits, b64 = list(), base64.b64encode(data).decode()
		for bs in range(65, 80):
			lines = list(b64[n:n+bs] for n in range(0, len(b64), bs))
			splits.append((bs - len(lines[-1]), lines))
		p_info()
		for line in sorted(splits)[0][1]: p(line)
	else:
		with open(opts.dst, 'wb') as dst: dst.write(data)

if __name__ == '__main__': sys.exit(main())
