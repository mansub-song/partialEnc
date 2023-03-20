package encrypt

var encryptOpt string

func SetEncryptOpt(opt string) {
	encryptOpt = opt
}

func GetEncryptOpt() string {
	return encryptOpt
}
