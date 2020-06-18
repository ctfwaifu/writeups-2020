> sorry for the broken links and lack of explaination, need some time to complete the writeups
# help_me
Whit3_D3vi1 - (discord) Whit3_D3vi1#3208

category: crypto, rev-eng

Hi, there i lost my flag and the source code which encrypted it :( Now i have only the encrypted text and the disassembly code. Help me get the flag.

Hint: here is the key 5Nzwbdkvm1VF1X3zc8d6kPd7MMTgSW9Dv1otpwkbPyggHqk5CaEHYwCD14vBdc3w86

files: [ciphertext.txt](https://github.com/ctfwaifu/writeups-2020/tree/master/Zh3r0-ctf/help_me/ciphertext.txt), [disassembled_code](https://github.com/ctfwaifu/writeups-2020/tree/master/Zh3r0-ctf/help_me/disassemble_code)

## process
This challenge is pretty similar to `snakes_everywhere`.
The ciphertext.txt file contained a python list of byte strings and numbers.
And the disassembled_code file had the disassembly (dis output) of the source code.

So the first thing I did is reconstruct the source code.
## reconstruction from disassembly
```python
from Crypto.Util.number import *
from binascii import hexlify, unhexlify
from flag import flag, key

if len(flag) == 48:
	fake_flag = 'zh3r0{l0l_thi5_i5_n0t_th3_fl4g}'

	def xor(str1, str2, num):
		return chr((ord(str1[num]) + num) ^ ord(str2[num]))

	def first_half(half_flag):
		return [hexlify( half_flag[i:i+4].encode() ) for i in range(0, len(half_flag), 4)]


	def second_half(half_flag):
		return [ bytes_to_long(half_flag[i:i+4].encode()) for i in range(0, len(half_flag), 4)]

	def encrypt(key, flag):
		final = []
		first_xor = [  xor(flag[:len(flag)//2], key[len(key)//2:], i) for i in range(len(flag)//2)]
		second_xor = [ xor(flag[len(flag)//2:], key[:len(key)//2], i) for i in range(len(flag)//2)]
		final += first_half(''.join(first_xor))
		final += second_half(''.join(second_xor))

		return final

	print(encrypt(key, flag))
```
and then I reversed the functions
## fail attempt
```python
def ss_reversed():
	# key = 'H3ll0_tbh_Th15_15_7h3_k3y_F0r_7hi5_ch4ll3ng3_atb'
	key = '5Nzwbdkvm1VF1X3zc8d6kPd7MMTgSW9Dv1otpwkbPyggHqk5CaEHYwCD14vBdc3w86'
	final = [b'03367345', b'46c39f41c3a8', b'1544651a', b'03451b28', b'77c3aac3a275', b'c39e16c3b6c3b2', 391124763, 121061897, 1396123432, 389813723487, 295339258400, 131682038629031]
	lf = 48                    # known flag length
	lfh = 24                   # lf half

	def first_half_reversed(final):
		half_flag = ''
		for i in final:
			half_flag += unhexlify(i).decode()
		return half_flag

	def second_half_reversed(final):
		half_flag = ''
		for i in final:
			half_flag += long_to_bytes(i).decode()
		return half_flag

	def xor_reversed(str1, str2, num):
		c = (ord(str1[num]) ^ ord(str2[num])) - num
		return chr(c)

	first_xor = first_half_reversed(final[:6])
	second_xor = second_half_reversed(final[6:])

	f1 = [xor_reversed(first_xor, key[len(key)//2:], i) for i in range(lfh)]
	f2 = [xor_reversed(second_xor, key[:len(key)//2], i) for i in range(lfh)]
	print(''.join(f1 + f2))

ss_reversed()
```
I made several changes to the script, compared the disassembly line by line. Did everything that came in my mind.
After spending several hours, I quit.
At some point I tried to decode the key in cyberchef. The magic function found that it was encoded in base58
which when applied to the key results in this
```
5Nzwbdkvm1VF1X3zc8d6kPd7MMTgSW9Dv1otpwkbPyggHqk5CaEHYwCD14vBdc3w86  (base58 decode) -->  wb==_0E390%9`d0`d0f9b0<bJ0u_C0f9:d049c==b?8b02E3
```
anyone having a bit more experience than a noob like me would recognise that it's rot47. But I ignored it.
After the ctf ended, I reattempted this chal and decoded the correct key.
```
5Nzwbdkvm1VF1X3zc8d6kPd7MMTgSW9Dv1otpwkbPyggHqk5CaEHYwCD14vBdc3w86
(base58 decode)
wb==_0E390%9`d0`d0f9b0<bJ0u_C0f9:d049c==b?8b02E3
(rot47 decode)
H3ll0_tbh_Th15_15_7h3_k3y_F0r_7hi5_ch4ll3ng3_atb
```

using this as the key and running the script again gets us the flag


### flag: zh3r0{pyth0n_di54ss3mbly_byt3c0d3_i5_s0_aw350m3}
