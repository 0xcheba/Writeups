# OniGiriCo — Writeup

**Category:** *web*

## Description

A shop of a company selling onigiri that hides its secret ingredient. A "follow the thread" type of machine designed to uncover the store's secrets.

## Solution

I started from exploring the web page. But I did not find anything useful.
Next, I enumerated directories using:

```Shell
gobuster dir -u http://ip:port/ -w /usr/share/wordlists/dirb/common.txt
```

This revealed several interesting paths:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico1.png" alt="Hidden directories"/>
</p>

The `/admin` page displayed a login form:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico2.png" alt="A login form"/>
</p>

The `/robots.txt` file, as usual, listed paths disallowed for indexing:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico3.png" alt="robots.txt contents"/>
</p>

One of the listed paths, `/onigiri-krewetki.txt`, contained a shrimp onigiri recipe and a crucial hint:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico4.png" alt="The note from onigiri-krewetka.txt"/>
</p>

It mentioned that the **secret ingredient** was stored in bob's home directory in a file named `secret.txt`.
While inspecting the HTML source code of the login page, I found this comment:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico5.png" alt="The hint in source code"/>
</p>

It suggested that the login panel is insecure. I submitted a test login and found the following cookie:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico6.png" alt="Possibly vulnerable cookie"/>
</p>

The cookie `admin_authenticated` was set to `false`. I changed it to `true` and reloaded the page:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico7.png" alt="Changing the value of cookie"/>
</p>

This granted me access to `panel.php`:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico8.png" alt="panel.php"/>
</p>

The first message from `admin@onigirico.com` contained another reference to secret ingredient:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico9.png" alt="Admin's message content"/>
</p>

Other messages were user comments.
I noticed that the URL in this page had a `?file=` parameter followed by a base64-encoded string (`%3D` URL encoded `=`):

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico10.png" alt="How URL looks like"/>
</p>

Decoding it confirmed that it pointed to a text file:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico11.png" alt="base64 decoding"/>
</p>

This suggested a potential **path traversal** vulnerability combined with base64 encoding. I base64-encoded the path to the `secret.txt` file — `../../../../../../home/bob/secret.txt`

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico12.png" alt="path to secret.txt file encoding"/>
</p>

To correct base64 padding, I replaced the last `o` character with an extra `=` to ensure proper decoding. After injecting this new string into the URL, I retrieved the flag:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/onigirico13.png" alt="The flag"/>
</p>