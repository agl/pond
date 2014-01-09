package main

const (
	msgCreatePassphrase = "Pond keeps private keys, messages etc on disk for a limited amount of time and that information can be encrypted with a passphrase. If you are comfortable with the security of your home directory, this passphrase can be empty and you won't be prompted for it again. If you set a passphrase and forget it, it cannot be recovered. You will have to start afresh."
	msgCreateAccount    = "In order to use Pond you have to have an account on a server. Servers may set their own account policies, but the default server allows anyone to create an account."

	msgDefaultServer     = "pondserver://ICYUHSAYGIXTKYKXSAHIBWEAQCTEF26WUWEPOVC764WYELCJMUPA@jb644zapje5dvgk3.onion"
	msgDefaultDevServer  = "pondserver://ZGL2WALCGXCKYBIHTWL5Q3TPCOEHSQB2XON5JHA2KHM5PJ3C7AFA@127.0.0.1:16333"
	msgKeyPrompt         = "Please enter the passphrase used to encrypt Pond's state file. If you set a passphrase and forgot it, it cannot be recovered. You will have to start afresh."
	msgIncorrectPassword = "Incorrect passphrase or corrupt state file"
	msgPleaseStartTor    = "Please start Tor or the Tor Browser Bundle. Looking for a SOCKS proxy on port 9050 or 9150..."
)
