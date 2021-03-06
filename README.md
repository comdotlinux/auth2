auth2
=====

Pure python 3 script for OpenSSH -- use with ForceCommand line of /etc/sshd_config for 2 step authentication

This script was inspired from articles when I read Linux Journal's article on YubiKey:
http://www.linuxjournal.com/magazine/yubikey-one-time-password-authentication

and digitalocean article : 
https://www.digitalocean.com/community/articles/how-to-protect-ssh-with-two-factor-authentication

However I needed something that required no extra device / Key and further needed needed to work with public key authentication.
Not password authentication.

So I stumbled upon : http://auth2.com/blog/2012/09/two-factor-authentication-for-ssh-connection-to-linux-servers/

But, I did not like that it used python to generate and compare keys but shell script was used to get the OTP and display messages.
Also there was no logging which I would very much like to have.

Further calling just one script seemed to be alluring.
So to scratch my itch :P this script was written.

Most of the stuff is from auth2.com/blog -- v.i.z. the generating and comparing OTP code are as-is from their python example.
This script 
1. Does not echo input OTP on input.

2. Reads the Secret key from configfile.

3. Can change the valid duration of OTP and OTP length from Config file

4. Name of command to be run if authentication is successful.

I have few Ideas about improving this like getting the $SSH_ORIGINAL_COMMAND like the shellscript on auth2 website does and logging failed IPs after extracting them from logs.
Also I would like to add multiuser capability and encrypting stored SECRET somehow.

Instructions for usage are same as on auth2 website:
1. Install libpam-google-authenticator & python3

2. On your Android / IOS / Blackberry Phone / Tablet install google-authenticator app (if you have enabled 2 step authentication for Google you might already have it)

3. Run google-authenticator with the user that will be used to login.

4. Answer the "Do you want authentication tokens to be time-based (y/n)" as y

5. Answer the "Do you want me to update your "$HOME/.google_authenticator" file (y/n)" as y

6. Note the Secret key in ssh.properties for Key SECRET

7. Setup authenticator app by opening it and selecting at top right 3 dots or menu > Set up account

8. Either Scan the QRCode generated by google-authenticator or simply enter the key by selecting appropriate option.

9. Copy the auth2.py, ssh.properties to /etc/ssh/

10. Create a logfile with filename as set in ssh.properties and makesure it is writable by user that is logging in.

11. Edit sshd_config and edit / add property ForceCommand=/etc/ssh/auth2.py

12. Reload / Restart the sshd service


Done! now every time you login via ssh you wil get a prompt asking for verification code :)

NOTE:- Please make sure the code generated by the authenticator app works by running auth2.py manually and entering OTP from app.
do check log file for message like "2013-09-24 14:49:06,900 Login successful."

Switched to DUO Security https://duo.com/ as it is one step less, entering the password is not required.
However I am now dependent upon their server uptime.
