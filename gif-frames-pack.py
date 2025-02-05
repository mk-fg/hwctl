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
			for x, y in it.product(range(w), range(h)):
				if isinstance(p := px[x, y], int): frame.append(None) # all-bg first frame?
				else: r, g, b, a = px[x, y]; frame.append((b<<16) + (g<<8) + r)
	assert len(frames) == len(frame_delays), [len(frames), len(frame_delays)]
	return adict(w=w, h=h, frames=frames, delays=frame_delays)

def frame_crop(frame, w, h):
	fx, fy, fw, fh = 0, 0, w, h
	for row in frame:
		if any(row): break
		else: fy += 1; fh -= 1
	if not fh: return 0, 0, 0, 0
	for row in reversed(frame):
		if any(row): break
		else: fh -= 1
	frame = list(zip(*frame))
	for col in frame:
		if any(col): break
		else: fx += 1; fw -= 1
	for col in reversed(frame):
		if any(col): break
		else: fw -= 1
	return fx, fy, fw, fh


def main(args=None):
	import argparse, textwrap
	dd = lambda text: re.sub( r' \t+', ' ',
		textwrap.dedent(text).strip('\n') + '\n' ).replace('\t', '  ')
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawTextHelpFormatter,
		usage='%(prog)s [options] image.gif [image.npx]', description=dd('''
			Convert GIF image pixels to a simpler packed format, for easy iteration/output.
			If output argument is not specified, dumps base64-encoded output to stdout.'''))
	parser.add_argument('src', help='GIF image file to convert.')
	parser.add_argument('dst', nargs='?', help='Output file name for packed pixel data.')
	parser.add_argument('-b', '--bg-color', metavar='hex', help=dd('''
		Hex-encoded background/dominant color to strip on exact pixel match.
		Default - auto-detected as most commonly used pixels.'''))
	parser.add_argument('-q', '--quiet', action='store_true', help=dd('''
		Don't print information about input/output sizes and compression to stderr.'''))
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	p_info = p_err if not opts.quiet else lambda *a,**kw: None
	p_info(f'Source file [ {opts.src} ]: {os.stat(opts.src).st_size:,d} B')
	img, bgc_set = get_frames(opts.src), opts.bg_color
	if len(bgc := opts.bg_color or '000') == 3: bgc = ''.join(bgc[n]*2 for n in range(3))
	if not bgc.startswith('0x'): bgc = f'0x{bgc}'
	bgc = int(bgc, 16)

	pal, cc = {bgc: 0}, dict()
	for frame in img.frames:
		for n, c in enumerate(frame):
			if c is None: c = frame[n] = bgc; continue
			c = frame[n] = c & 0xffffff # strip A from ABGR, if any
			if c not in pal: pal[c] = len(pal)
			cc.setdefault(c, 0); cc[c] += 1
	assert len(pal) <= 256, len(pal)
	bgc_detected = sorted((v, k) for k,v in cc.items())[-1][1]
	if bgc_set: assert bgc in cc, [bgc, bgc_detected]
	elif bgc != bgc_detected:
		if bgc in cc: pal[bgc] = len(pal)
		else: # replace default bgc in color=None pixels
			for frame in img.frames:
				for n, c in enumerate(frame):
					if c == bgc: frame[n] = bgc_detected
			del pal[bgc]
		pal[bgc_detected], bgc = 0, bgc_detected

	w, h, nf = 16, 8, len(img.frames)
	cb_pack = (cb := math.ceil(math.log2(cn := len(pal)))) < 5
	p_info(f'Palette colors = {cn}, color-bits = {cb}, bg = {bgc:x}, pack = {cb_pack}')

	frame_bs_list = list()
	for ms, frame in zip(img.delays, img.frames):
		assert (msb := ms // 10) == ms/10 and msb < 256, ms
		frame = list(list(pal[c] for c in cc) for cc in it.batched(frame, n=w))
		fx, fy, fw, fh = frame_crop(frame, w, h)
		frame_bs_list.append(frame_bs := bytearray(2 + fw * fh))
		if not fw: frame_bs_list[-1] = b'\0\0'
		else:
			struct.pack_into( 'BBB',
				frame_bs, o := 0, msb,
				(fx<<4) + fy, ((fw-1)<<4) + fh-1 )
			if not cb_pack:
				for row in frame[fx:fx+fw]:
					for c in row[fy:fy+fh]: frame_bs[3+o] = c
			else:
				frame_n = frame_bits = 0
				for row in reversed(frame[fx:fx+fw]):
					for c in reversed(row[fy:fy+fh]):
						frame_n <<= cb; frame_n |= c; frame_bits += cb
				frame_bs_list[-1] = frame_bs[:3] + frame_n.to_bytes(math.ceil(frame_bits / 8), 'big')
	assert len(frame_bs_list) == nf, [len(frame_bs_list), nf]

	with io.BytesIO() as dst:
		dst.write(struct.pack('BBH', w, h, nf))
		for c, n in pal.items():
			if not n: continue # designated bg color
			r, g, b = (c>>16)&0xff, (c>>8)&0xff, c&0xff
			dst.write(struct.pack('BBB', g, r, b))
		dst.write(b'\0\0\0')
		for frame_bs in frame_bs_list: dst.write(frame_bs)
		data = zlib.compress(dst.getvalue(), level=9, wbits=-15)

	p_info(f'Output file [ {opts.dst or "-"} ]: {len(data):,d} B (zlib level=9 wbits=-15)')
	if not opts.dst:
		splits, b64 = list(), base64.urlsafe_b64encode(data).decode()
		for bs in range(65, 80):
			lines = list(b64[n:n+bs] for n in range(0, len(b64), bs))
			splits.append((bs - len(lines[-1]), lines))
		p_info()
		for line in sorted(splits)[0][1]: p(line)
	else:
		with open(opts.dst, 'wb') as dst: dst.write(data)

if __name__ == '__main__': sys.exit(main())
