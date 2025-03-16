# historical_ciphers

## Ceasar, Affine Ciphers
![My Image](https://github.com/MrkFrcsl98/historical_ciphers/blob/main/23r432r32r243243242.jpg?raw=true)


## Ceasar Cipher 
Ceasar cipher is one of the oldest ciphers ever existed, was used in the ancient times when Roman emperor julius cesar
wanted to exchange secret information.
Ceasar cipher is a monoalphabetic substitution cipher, where each letter in the plaintext is replaced
by another one based on the shift size(key). During encryption, each letter is shifted to right by n positions,
while during decryption the process is reversed, subtracting instead of adding(left shifting).
This cipher is vulnerable to frequency analysis techniques, for example if the key is 4, and the message is "hello", 
the result will be:
h = h + 4 = l
e = e + 4 = i
l = l + 4 = p
l = l + 4 = p
o = o + 4 = s
so the ciphertext would be: lipps
as we can see the letter "l" always has the same output when shifted, is very easy to crack the algorithm as only 26 
keys are to be tested.
### Ceasar Encryption Formula: E(x) = (x + k) mod 26
### Ceasar Decryption Formula: D(y) = (y - k) mod 26

## Affine Cipher 

Affine cipher is also a monoalphabetic substitution cipher just like ceasar.
more secure than Ceasar Cipher but still weak due to easy brute force attacks and frequency analysis.
Affine Cipher spits the key in 2 parts(A, B), is crucial that A have a modular inverse
under modulo 26, otherwise it will not work, this means that A and 26 (the modulo) must
be coprime!! A must be coprime with the modulo because during decryption is required to
compute the multiplicative inverse of A mod 26, and if they are not coprime the
decryption is not possible as the equation for decryption will have no solution. Another
reason for A to be coprime with modulo M is to ensure unique decryption, if A and 26 are
not coprime, the decryption process can lead to multiple plaintext letters potentially
mapping to the same ciphertext letter, undermining the cipher's reliability and
security. If A and 26 are not coprime, will eventually lead to security
weaknesses, if A is not coprime with 26, the cipher becomes more predictable,
and easier to break, the redundancy introduced by non-coprime A values
reduces the effective key space, making the cipher more vulnerable
to cryptanalysis.
### Affine Encryption Formula: E(x) = (A * X + B) mod 26
### Affine Decryption Formula: D(y) = A^-1 * (Y - B) mod 26


## Vigenere Cipher 

Vigenere Cipher is a polyalphabetic substitution cipher, meaning that the same letter will not
guarantee to have the same variant like in Ceasar of affine cipher. Vigenere cipher do not use
a shift key, instead, vigenere cipher uses a keywork to encrypt/decrypt the message. 
This keyword must be the same length of the message. It works similar to OTP stream ciphers, where
a keystream is generated. Each letter in the message is added with the letter in the keystream to
produce the ciphertext. During decryption, the process repeats in reverse order.
### Vigenere Encryption Formula: E(x) = (Pi + Ki) mod 26
### Vigenere Decryption Formula: D(y) = (Ci - Ki) mod 26

These ciphers are very easy to understand, and they all use modular arithmetic operations to derive the product.
