# easyjerk writeup 

**Platform:** *crackmes.one*

**Link:** https://www.crackmes.one/crackme/67fa22568f555589f3530a94

**Difficulty:** *1.8*

**Author:** che6a


## Description (from ckarckme's author)

This is a simple CrackMe for Linux x86_64. The goal is to find the correct serial that allows access. No packers or anti-debug tricks are used. Compiled with GCC. Enjoy and good luck :)

## Solution

First, I found a piece of code responsible for displaying messages:

<p align="center">
<img src="/resources/easyjerk0.png" alt="Piece of disassembly with output"/>
</p>

Here we can see the `check_serial` function, which, as the name suggests, checks the serial we input.

Inside the function, we can see 8 bytes loaded into the stack frame and a counter initialized to `0x8`:

<p align="center">
<img src="/resources/easyjerk1.png" alt="Piece of disassembly with bytes"/>
</p>

If you convert these 8 bytes into a string, you get Xn\`k{Vfu. However, this is not the final password.

Next, the program checks the length of our input, and if it is not equal to 8, it terminates.

Otherwise, the program enters a loop with the `transform` function. This function processes each character we entered, along with a counter, and applies several transformations:

1. It sums counter with 0x7
2. xor our byte with counter we got
3. Sums the result of previous change and 0xd
4. Finally, "and" the result of previous change with 0x7f

To find the correct input bytes, I wrote the following script:

```python
target_bytes = bytes([0x58, 0x6e, 0x60, 0x6b, 0x7b, 0x56, 0x66, 0x75])
result = bytearray()
counter = 0

for i, target in enumerate(target_bytes):
	for byte in range(256):
		temp_counter = counter + 0x7
		get_byte = byte ^ temp_counter
		get_byte = get_byte + 0xd
		get_byte = get_byte & 0x7f
		if get_byte == target:
			result.append(byte)
			counter += 1
			break
			
			
print(result)
```
The result of running the script was: `bytearray(b'LiZTeETf')`

Then I checked whether the password was correct — and it worked:

<p align="center">
<img src="/resources/easyjerk2.png" alt="The result with the correct password"/>
</p>

## Conclusion

A simple and clean CrackMe with no protection — great for practicing reverse engineering basics and Python automation.