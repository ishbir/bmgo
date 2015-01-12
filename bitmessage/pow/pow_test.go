package pow

import (
	"crypto/rand"
	"testing"
)

const nonceTrialsPerByte = 1000
const payloadLengthExtraBytes = 1000
const lifetime = 60 * 60 * 24 * 5 // 5 days
var payload []byte = make([]byte, 3402)

func init() {
	_, err := rand.Read(payload)
	if err != nil {
		panic("unable to read random bytes: " + err.Error())
	}
}

type calculateTargetTest struct {
	ttl         int
	payloadLen  int
	targetValue uint64
}

var calculateTargetTestCases = []calculateTargetTest{
	{60 * 60 * 24 * 5, 3402, 551983724040},
	{60 * 60 * 24 * 28, 563421, 862017809},
	{60 * 60 * 24 * 90, 87996, 1732319784},
	{60 * 60 * 24 * 45, 478622, 637550899},
}

func TestCalculateTarget(t *testing.T) {
	for n, testcase := range calculateTargetTestCases {
		target := CalculateTarget(testcase.payloadLen, testcase.ttl,
			nonceTrialsPerByte, payloadLengthExtraBytes)
		if target != testcase.targetValue { // calculated from code
			t.Error("for case ", n+1, " got", target, "expected",
				testcase.targetValue)
		}
	}
}

func TestDoSequential(t *testing.T) {

}

func TestCheck(t *testing.T) {

}
