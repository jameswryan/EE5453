# EE5453 Assignment 1 - Semi Automated Cryptanalysis of Monoalphabetic Substitution Cipher


## Introduction
  In this report we detail a semi-automated cryptanalysis (SAC) program designed to attack the 'Even-Less-Simple-Substitution' cipher (ELSSC) presented in class.

  To understand the attack used in the program, it is helpful to think of the ELSSC as a block cipher with a block length of 1.
  Additionally, the ELSSC key is the same as the encryption of the english alphabet.
  Because of this frequency analysis can be performed on the ciphertext to enable not only recovery of the plaintext, but full key recovery.


## Attack
  The attack is a simplified frequency analysis attack, 
  using the preexisting knowledge that the english alphabet (ABCDEFGHIJKLMNOPQRSTUVQXYZ) sorted by decreasing frequency is EATOINSHRDULCMWFGYPBVKJXQZ.
  This preexisting knowledge combined with the properties of the ELSSC discussed in the introduction implies that the key can be recovered by sorting the ciphertext letters by decreasing frequency.
  Because the ELSSC is invariant under permutation of the alphabet, this is (close to) a permuted version of the key!
  To recover the plaintext, letters in the ciphertext are directly substituted using the recovered key.
  
  For short messages, the recovered key may not be correct, owing to differences between the particular message and a more representative sample of english text.
  A SAC can be performed by continually asking a cryptanalyst whether or not changes are needed to the recovered key.
  
## Program
  The attached program is written in Rust, using rustc version 1.63.0.
  The program directly implements the SAC discussed in the 'Attack' section of this report.
  The program makes use of several external libraries for non-core features such as user input and CLI parsing.
  
  The program contains source code comments explaining how it works, but not the details of the attack, which are outlined above.
  A screenshot of the program after operation is shown below.
    
  ![Using the SAC Program](operation.png "Using the SAC program")
    
  The workflow of the program is:

  0. Read encrypted input from file passed as command line argument
  1. Perform frequency analysis to get probable key
  2. Decrypt part of the ciphertext with probable key.
  3. Display progress to attending cryptanalyst, modify key based on cryptanalyst's feedback. 
  4. If the cryptanalyst is unsatisfied, go back to step 2.
  5. The cryptanalyst is satisfied, so fully decrypt ciphertext and write to file 'decrypted' in the current working directory.
  
  The cryptanalyst working with the program is expected to be familiar with the details of the attack used, so any English-speaking elementary-school student should be capable.
