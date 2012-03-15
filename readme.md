## Decryption Analysis of One-Time-Pad

One-time-pad/key encryption is more or less the only completely secure form of encryption.  However, when one uses a one-time-key more than once, then it opens itself to analysis.  This program takes an input of a text message containing encrypted "messages" (the more, the better) and analyses them as best it can (you can review the code and comments for exact details of the implementation).  From there, the decrypted text isn't nearly complete, but there is typically enough for a human to fill in the blanks.

### Running the program

You run the program with:

```bash
ruby decryptOTP.rb ct_file
```

where ct_file is the file containing the encrypted texts, with a blank line separating each

### Compeleting the manual process

For any blanks you wish to fill in, just type:

'''bash
ctext_num,position,value

i.e.

if you see, in the first ciphertext

```bash
T . .  c a t  a n d  t h e  d o g . .

you could type

```bash
1,2,he

to complete

 ```bash
T h e  c a t  a n d  t h e  d o g . .


### Other stuff

This is 100% just a quick project that resulted from a cryptography course, and I added some extensions to make the process as automatic as I could, so....no complaints bitte.