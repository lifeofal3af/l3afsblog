# Hey there!

This is my writeup for the [POST practice challenge on CTFlearn](https://ctflearn.com/challenge/114)

First, I opened up the URL and opened the page source.

I found that an admin username and password is found in the page source as shown here:

![page source of said challenge](https://github.com/user-attachments/assets/c372e8e9-989d-4ae2-8aee-31e5790c261d)

Since this site accepts POST data (according to the page content), I decided to use curl to form a request.

Assuming that the username parameter is "username" and the password follows suit with it being "password" i made this command:

`curl 165.227.106.113/post.php -d "username=admin&password=71urlkufpsdnlkadsf"`

Which returns this value:

`<h1>flag{[REDACTED]}</h1>`

Thanks for reading!


