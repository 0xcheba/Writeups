# Painted Black — Writeup

**Category:** *forensics*

## Description

The Ravenbook Police Department is using a new product to black out Personally identifiable information (PII) from their Word documents before making them public. We heard through the grapevine that this product is not that safe. Can you check this document and retrieve the blacked out information?

## Solution

The `.docm` file was provided:

![The original file](../resources/WHY2025%20CTF/paintedblack1.png)

The blacked-out text looked encrypted, for example, one of the strings in the file: `q~luaj*-:"#j!rs4v,k| <u-9'$wity8$9!.q`.
This is a Word file, so I could unzip it and get more information about the file.
The first interesting thing I found was the VBA script (`./word/vbaProject.bin`):

![The VBA script](../resources/WHY2025%20CTF/paintedblack2.png)

Here I noticed that the script encrypts/decrypts the selected text with `0x7B` byte and the lowercased username of the person who created the file, without spaces and starting with the second byte. So I looked for the username and found it in the `./docProps/core.xml` file:

![The username of file author](../resources/WHY2025%20CTF/paintedblack3.png)

After processing the encrypted text using the extracted username, I recovered the flag:

![The recovered flag](../resources/WHY2025%20CTF/paintedblack4.png)
