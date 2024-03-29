## Decryption Analysis of One-Time-Pad

One-time-pad/key encryption is more or less the only completely secure form of encryption.  However, when one uses a one-time-key more than once, then it opens itself to analysis, and possibly decryption.  This program takes an input of a text file containing encrypted "messages" (the more, the better) and analyzes them as best it can (you can review the code and comments for exact details of the implementation).  From there, the decrypted text isn't nearly complete, but there is typically enough for a human to fill in the blanks.

### Running the program

You run the program with:

```bash
ruby decryptOTP.rb ct_file
```

where ct_file is the file containing the encrypted texts, with a blank line separating each.

#### Compeleting the manual process

For any blanks you wish to fill in, just type:

```bash
ctext_num,position,value
```

i.e.

if you see, in the first ciphertext

```bash
ct 1: T . .  c a t  a n d  t h e  d o g . .
```

you could type

```bash
1,2,he
```

to complete

```bash
ct 1: T h e  c a t  a n d  t h e  d o g . .
```

### Options

You can type 'D' to toggle analysis mode, which displays the position of each character above it, for ease in manual decryption

You can type 'Q' to quit

...and that is it, for now.



### Other stuff

This is 100% just a quick project that resulted from a cryptography course, and I added some extensions to make the process as automatic as I could, so....no complaints bitte.