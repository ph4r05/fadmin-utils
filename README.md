# FI MUNI Auth login

```bash
fadmin-login --help

fadmin-login --user xtester --key-file password_file
```

Or with keyring

```bash
keyring set https://fadmin.fi.muni.cz/auth/sit/wireless/login2.mpl xtester
fadmin-login --user xtester --key-ring
```


