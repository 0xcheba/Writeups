# The Wizard — Writeup

**Category:** *forensics*

## Description

After some issues involving a robe and wizard hat, HR decided it was best if we let go of this old developer we had. However with him gone we now lost access to some systems, since he had his own way of saving passwords. Can you help us out?

## Solution

Several files from the user's home directory were provided:

![](../resources/WHY2025%20CTF/thewizard1.png)

The `.bash_logout`, `.bashrc`, and `.profile` files contained no useful information.
The `.pwfault` file appeared to contain encrypted (or obfuscated) data:

![](../resources/WHY2025%20CTF/thewizard2.png)

There was also a `.viminfo` file containing command and file history:

![](../resources/WHY2025%20CTF/thewizard3_0.png)
![](../resources/WHY2025%20CTF/thewizard3_1.png)

The following table explains all the commands used to perform data transformation:

| The command        | What does it do                                   |
| ------------------ | ------------------------------------------------- |
| `:v/?/d`           | Removes all lines that don't contain a "?" symbol |
| `:%s,[^a-f0-9],,g` | Removes allcharacters that are not in hex         |
| `:%s/\n//`         | Removes all newline characters                    |
| `:s/dd/`           | Removes the first "dd"                            |
| `:%s/^...../flag{` | Swaps first five characters to "flag{"            |
| `:%s/.$/}`         | Swaps the last characters to "}"                  |

I replicated all of the recorded commands and successfully recovered the flag:

![](../resources/WHY2025%20CTF/thewizard4.png)