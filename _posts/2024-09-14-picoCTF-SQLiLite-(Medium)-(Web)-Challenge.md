# Hey there!
Today, I tackled the PicoCTF SQLite Medium Web Challenge. Here's a step-by-step breakdown of how I solved it:

## Initial Screen

We are greeted with the following screen:

![Initial Screen](https://github.com/user-attachments/assets/5ae3c6dc-a6f7-454c-9538-6c2c0b1a7c04)

## Login Failed Screen

Entering random nonsense brings us to this screen with a "Login Failed" footer and the SQL query used to check if the username and password are in the database:

![Login Failed Screen](https://github.com/user-attachments/assets/efecb130-fb6d-4f93-9a27-5b3c02266ee4)

## SQL Injection

With the SQL query visible, we can craft a simple SQL injection in the username field. This will cancel out everything and allow us to gain access:

![SQL Injection](https://github.com/user-attachments/assets/d1a79185-b6de-40b6-a414-f8ecff53790c)

## Logged In Screen

This brings us to the logged-in screen with the text "Logged in! You can see the flag, it is in plain sight":

![Logged In Screen](https://github.com/user-attachments/assets/e6e68445-561e-4c82-8018-f9b56b14e9f0)

## Viewing the Source

By right-clicking on the page and selecting "View Page Source," we can see the flag:

![View Page Source](https://github.com/user-attachments/assets/cafbe236-6b0c-4584-a0d5-09c3cae02fc6)

## The Flag

The flag is: `picoCTF{L00k5_l1k3_y0u_solv3d_it_ec8a64c7}`

Sorry if this writeup is short today. I will post more today, InshaAllah.

