package pow

import (
	"crypto/rand"
	"runtime"
	"testing"
)

const nonceTrialsPerByte = 1000
const payloadLengthExtraBytes = 1000

var payload []byte = make([]byte, 3402)

func init() {
	_, err := rand.Read(payload)
	if err != nil {
		panic("unable to read random bytes: " + err.Error())
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
}

type calculateTargetTest struct {
	ttl         int
	payloadLen  int
	targetValue uint64
}

// Calculated using Python code
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

type doTest struct {
	target      uint64
	initialHash []byte
	nonce       uint64
}

var doTestCases = []doTest{
	{950742058885505, []byte{0x8C, 0x0D, 0x19, 0x92, 0x42, 0x66, 0x66, 0xDE}, 11676},
	{469608989833017, []byte{0x3B, 0x9E, 0xB9, 0xE6, 0xB3, 0x7D, 0xCC, 0xCA}, 17725},
	{465517482044422, []byte{0x5B, 0xF2, 0x6C, 0xB7, 0xC6, 0x90, 0xB5, 0x5C}, 8507},
	{711627882338497, []byte{0xD0, 0xD6, 0x4A, 0xFE, 0xB8, 0xDA, 0x94, 0x18}, 59420},
	{593050836922707, []byte{0xCB, 0xC0, 0xE3, 0xC7, 0x39, 0xB7, 0xC4, 0x80}, 11027},
	{321018695700117, []byte{0x1E, 0x53, 0x1E, 0xD3, 0x98, 0x22, 0x71, 0x3B}, 21814},
}

func TestDoSequential(t *testing.T) {
	for n, testcase := range doTestCases {
		nonce := DoSequential(testcase.target, testcase.initialHash)
		if nonce != testcase.nonce {
			t.Error("for case", n+1, "got nonce", nonce, "expected",
				testcase.nonce)
		}
	}
}

func TestDoParallel(t *testing.T) {
	for n, testcase := range doTestCases {
		nonce := DoParallel(testcase.target, testcase.initialHash,
			runtime.NumCPU())
		if nonce < testcase.nonce { // >= is permitted
			t.Error("for case", n+1, "got nonce", nonce, "expected",
				testcase.nonce)
		}
	}
}

var benchmarkCase = doTest{9008795083716, []byte{0x2B, 0x5D, 0x67, 0x63, 0xD9,
	0x8C, 0xE1, 0xA7}, 0} // result is irrelevant

func BenchmarkDoSequential(b *testing.B) {
	DoSequential(benchmarkCase.target, benchmarkCase.initialHash)
}

func BenchmarkDoParallel(b *testing.B) {
	DoParallel(benchmarkCase.target, benchmarkCase.initialHash,
		runtime.NumCPU())
}

func TestCheck(t *testing.T) {

}
