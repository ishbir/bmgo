package pow

/*
Calculate the target POW value. From: https://bitmessage.org/wiki/Proof_of_work
*/
func calcTarget() float64 {

}

/*
Check if the POW is sufficient for an object.
*/
func IsSufficient(object []byte,
	ttl, nonceTrialsPerByte, payloadLengthExtraBytes uint) bool {

}

/*
Do the POW using multiple go-routines
*/
func Do() {

}
