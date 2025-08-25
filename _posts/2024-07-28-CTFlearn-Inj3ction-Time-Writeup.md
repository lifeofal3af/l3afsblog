# Hey there!

In this writeup, I will be cracking the [CTFlearn Inj3ction Time Challenge](https://ctflearn.com/challenge/149)

At first, I tried using union selecting or something as the challenge said to do:

![challenge description](https://github.com/user-attachments/assets/a573d128-e861-4d84-ae69-7a25663d6660)

I knew that there were about 3 or so columns in the current database so I ran `?id=1+union+select+1,2,3` But that returned nothing.

So I thought that maybe adding another one would work so I used the command `?id=1+union+select+1,2,3,4` which returns:

![returned items](https://github.com/user-attachments/assets/a0f85876-a145-4f82-a8b4-d4c126b3e987)

To make sure I am going somewhere with this, I went ahead and replaced `3` with `version()` as seen below:

![versionnumber](https://github.com/user-attachments/assets/f1853cd1-71f1-4f98-8bd0-6e12ddea5dfe)

Now we're getting somewhere.

I then decided to look into one of the articles from [acuentix](https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/) (which is found in the comments of the challenge) about SQLI as I am not that advanced in the subject (which I guess wouldn't be counted as cheating) and ran the command recommended by the article which is injecting

`(SELECT+group_concat(table_name)+from+information_schema.tables+where+table_schema=database())`

So then I did that and got these results:

![oohshiny](https://github.com/user-attachments/assets/e51b4bf9-2bb3-42ee-9cf8-4b24536b6db9)



i then ran the command `(SELECT+*+FROM+w0w_y0u_f0und_m3)`

Which then gave me this:

![Flag](https://github.com/user-attachments/assets/120ccf69-ff21-4d84-8705-97ec6a1bda29)

Thanks for reading!


