# skidibi — Writeup

**Category:** *reverse*

## Solution

I was given given a file containing the following text:

<p align="center">
<img src="../../resources/BCACTF 6.0/skibidi1.png" alt="The source file"/>
</p>

It looked like a cipher or an esolang, so I started researching this using the file extension. I found these pages:  [GitHub](https://github.com/Gen-Alpha-Inc/skibidi-lang) and [esolang.org](https://esolangs.org/wiki/Gen_Alpha_Brainrot)

Using the information from those pages I wrote a simple converter that translates `skibidi` to `Brainfuck`:

```python
convert = {
	"gyatt": "-",
	"sigma": "+",
	"ohio": ".",
	"skibidi": ">",
	"grimaceshake": "[",
	"rizz": "<",
	"fanumtax": "]",
	"blud": ","
}

code = input()
syms = code.split()
decode = "".join(convert.get(sym, '') for sym in syms)
print(decode)
```

This produced the following Brainfuck code:

<p align="center">
<img src="../../resources/BCACTF 6.0/skibidi2.png" alt="The Brainfuck code"/>
</p>

I used an online Brainfuck interpreter to run this code, which output the following string: `bcactf{516m4_516m4_0n_7h3_w411_wh0_15_7h3_5k181d1357_0f_7h`

It looked like a flag, it was missing the closing brace and the phrase was incomplete. Next, I looked for the whole phrase and found it here: [allpoetry.com]([https://allpoetry.com/poem/18007983-sigma-sigma-on-the-wall](https://allpoetry.com/poem/18007983-sigma-sigma-on-the-wall)...-by-Gigasigma)

So, the final flag was: bcactf{516m4_516m4_0n_7h3_w411_wh0_15_7h3_5k181d1357_0f_7h3m_411}