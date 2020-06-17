> sorry for the broken links and lack of explaination, need some time to complete the writeups
# snakes_everywhere
### {author_name}

category: rev eng

[desciption]

files: py_dis1, snake.txt

## process
At first glance at `snake.txt` it was clear that it was some encrypted text, which I assumed to be the complete flag

Next I opened the py_dis1 file, which contains some ascii data. the contents looked like a sort of disassembly.
A quick google search of `py dis` reveals some information about the dis standard python library, which is used to
disassemble python code. Again, I assumed this must be the disassembly of the source code which was used to generate the snake.txt file.

Unfortunately there is no tool for reconstructing python source from it's disassembly. So I had to do it manually.
But it turned out to be far easier than I thought. I also took help from the dis module docs. For every new instruction I just
searched it up in that doc file and the description was there :D


here is the reconstruction
## reconstruction from given disassembly
```python
from flags import flag1
flag = flag1
fake_flag = 'zh3r0{fake flag}'

key = 'I_l0v3_r3v3r51ng'

if len(flag) == 38:

	def xor(str1, str2): return chr(ord(str1) ^ ord(str2))

	ciphertext = ''

	for i in range(len(flag) // 3):
		ciphertext += chr( ord(key[i]) * ord(flag[i]) - i )

	for i in range(len(flag) // 3, (len(flag) // 3) * 2):
		ciphertext += chr( ord(flag[i]) * ord(key[i % len(key)]) + i)

	for i in range(len(key) // 2, len(flag)):
		ciphertext += xor(key[i % 16], flag[i])

	file = open('ciphertext.txt','w')
	print(len(ciphertext))
	file.write(ciphertext)
	file.close()
```
The dis output of this code lines up pretty well with the one provided by author.

So next step was reversing this source to generste the flag given the cipher.

and here it is
## solution script
> the output is obfuscated
```python
def ss_reverse():
	key = 'I_l0v3_r3v3r51ng'
	cipher = '⋊⚗ᖂᕝᘜ\u187cᶪ㗛᜔\u2fe7ᘓヱᎷጱ\u2d2c\u2e54᮹⪾ゖণ㉒\u139b⠪㗹G\x1e\\\x1cjU\x07\x14(,\x1f\x03\x1bQ3\x0bl\x1f@RC\x02\x1c\x1e\x16\x1aXC\x0fN'

	l_f = 38        # known length of flag

	f = ''
	for i in range(l_f // 3):
		f += chr(int( (ord(cipher[i]) + i) / ord(key[i]) ))
	for i in range(l_f // 3, l_f // 3 * 2):
		f += chr(int(( ord(cipher[i]) - i ) / ord(key[i % len(key)])))
	for i in range(24,54):
		f += xor(key[i % 16], cipher[i])

	print(f)

def xor(str1, str2): return chr(ord(str1) ^ ord(str2))

ss_reverse()
```

output: ```zh3r0{Python_disass3mblython_disass3mbly_is v3ry_E4sy}```

### flag: zh3r0{Python_disass3mbly_is_v3ry_E4sy}
