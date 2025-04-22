# **Flag Hunters Writeup**

**Platform:** *picoGym*

**Difficulty:** *Easy*

**Category:** *Reverse Engineering*



## **Description**

In this challenge, we are provided with an `nc` command to connect to the target host:

```nc verbal-sleep.picoctf.net 56688```

Additionally, we are given a [download link](https://challenge-files.picoctf.net/c_verbal_sleep/9f2b86c1e1068d492f783b106f4535aeb137b0c0e31e43351f8cb82a39456a84/lyric-reader.py) to the source code of the service.

Upon connecting, the server outputs lines from a song defined in the script. After several lines, the program prompts the user to provide input.



## **Solution**

### **Execution flow**

1. **Initial behavior with any input**

   If we provide any input, it will proceed through the song and terminate without giving the flag.

2. **Each script line is split by** `;`

   The core processing loop splits each line of the song using the `;` character:

   ```python
   for line in song_lines[lip].split(';'):
   ```



3. **Single entry point for user input**

   The program provides a single location for user input:

   ```python
   elif re.match(r"CROWD.*", line):
       crowd = input('Crowd: ')
       song_lines[lip] = 'Crowd: ' + crowd
       lip += 1
   ```



4. **Input is embedded into the song text**

   Any string submitted by the user is formatted as `Crowd: <user_input>` and replaces the placeholder line `CROWD (Singalong here!);`:

   ```
   [REFRAIN]
   We’re flag hunters in the ether, lighting up the grid,
   No puzzle too dark, no challenge too hid.
   With every exploit we trigger, every byte we decrypt,
   We’re chasing that victory, and we’ll never quit.
   CROWD (Singalong here!);
   RETURN
   ```



5. **The** `lip` **variable is a line pointer**

   The variable `lip` serves as a line counter — it points to the current line in song being executed in the script.

6. `RETURN` **instruction modifies control flow**

   A line starting with `RETURN N` causes the `lip` variable to be updated with the line index `N`, altering the control flow.

   ```python
   elif re.match(r"RETURN [0-9]+", line):
       lip = int(line.split()[1])
   ```





### **Exploiting the logic**

7. **Flag-containing lines exist but are inaccessible by default**

   There are lines containing the flag, but they are not reachable through the standard execution flow — because `lip` starts at a non-zero value and doesn’t naturally visit those lines.

   ```python
   flag = open('flag.txt', 'r').read()
   
   secret_intro = \
   '''Pico warriors rising, puzzles laid bare,
   Solving each challenge with precision and flair.
   With unity and skill, flags we deliver,
   The ether’s ours to conquer, '''\
   + flag + '\n'
   
   
   song_flag_hunters = secret_intro +\
   '''
   
   [REFRAIN]
   ```

   

8. **Crafting the payload**

   We can inject the semicolon-splitting behavior to smuggle a `RETURN` instruction into the script line:

   `;RETURN 0`

   After processing, the embedded line becomes:

   `Crowd: ;RETURN 0`

   After splitting the line becomes two parts: `Crowd: ` and `RETURN 0`. The second part will be interpreted as an instruction.

   When `RETURN 0` is processed, `lip` is set to 0, redirecting the execution to the first line — which contains the hidden flag.

   ```
   Command line wizards, we’re starting it right,
   Spawning shells in the terminal, hacking all night.
   Scripts and searches, grep through the void,
   Every keystroke, we're a cypher's envoy.
   Brute force the lock or craft that regex,
   Flag on the horizon, what challenge is next?
   
   We’re flag hunters in the ether, lighting up the grid,
   No puzzle too dark, no challenge too hid.
   With every exploit we trigger, every byte we decrypt,
   We’re chasing that victory, and we’ll never quit.
   Crowd: ;RETURN 0
   
   Echoes in memory, packets in trace,
   Digging through the remnants to uncover with haste.
   Hex and headers, carving out clues,
   Resurrect the hidden, it's forensics we choose.
   Disk dumps and packet dumps, follow the trail,
   Buried deep in the noise, but we will prevail.
   
   We’re flag hunters in the ether, lighting up the grid,
   No puzzle too dark, no challenge too hid.
   With every exploit we trigger, every byte we decrypt,
   We’re chasing that victory, and we’ll never quit.
   Crowd: 
   Pico warriors rising, puzzles laid bare,
   Solving each challenge with precision and flair.
   With unity and skill, flags we deliver,
   The ether’s ours to conquer, picoCTF{█████████████████████████}
   
   
   [REFRAIN]
   ^C
   
   ```





## **Conclusion**

By injecting `;RETURN 0` into the user input, we hijack the control flow to access restricted lines in the script, effectively bypassing program limitations and revealing the flag.

