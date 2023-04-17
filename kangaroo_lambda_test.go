package sm2elgamal

// https://ece.uwaterloo.ca/~p24gill/Projects/Cryptography/Pollard's_Rho_and_Lambda/Pollard's_Lambda_Method.html
// https://ece.uwaterloo.ca/~p24gill/Projects/Cryptography/Pollard's_Rho_and_Lambda/Project.pdf

import (
	"crypto/elliptic"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

type kangarooLambda struct {
	b                        uint64
	sqrtRootOfRange          uint64
	d                        uint64
	alpha                    float64
	beta                     float64
	tameKangarooJumps        uint64
	distanceOfTameFromOrigin uint64
	tameKangarooHistory      map[string]uint64
}

func NewKangarooLambda(b uint64) *kangarooLambda {
	kl := &kangarooLambda{}
	kl.b = b
	v := new(big.Int)
	v.SetUint64(b)
	v.Sqrt(v)
	kl.sqrtRootOfRange = v.Uint64()
	kl.d = uint64(v.BitLen())
	v.SetUint64(kl.d)
	kl.d += uint64(v.BitLen()) - 2
	kl.beta = 1.39
	kl.alpha = math.Sqrt(1-math.Exp(-kl.beta)) / (2 * kl.beta * (2 - math.Exp(-kl.beta)))
	kl.tameKangarooJumps = uint64(kl.alpha * kl.beta * float64(kl.sqrtRootOfRange))

	tameX, tameY := sm2.P256().ScalarBaseMult(big.NewInt(int64(b)).Bytes())
	tameBytes := elliptic.MarshalCompressed(sm2.P256(), tameX, tameY)
	var totalTameDistance uint64
	kl.tameKangarooHistory = make(map[string]uint64)
	kl.tameKangarooHistory[string(tameBytes)] = totalTameDistance

	for i := uint64(0); i < kl.tameKangarooJumps; i++ {
		v := new(big.Int).Mod(tameX, big.NewInt(int64(kl.d)))
		v.Add(v, big.NewInt(1))
		v.Exp(big.NewInt(2), v, sm2.P256().Params().N)
		x, y := sm2.P256().ScalarBaseMult(v.Bytes())
		tameX, tameY = sm2.P256().Add(tameX, tameY, x, y)
		totalTameDistance += v.Uint64()
		tameBytes = elliptic.MarshalCompressed(sm2.P256(), tameX, tameY)
		kl.tameKangarooHistory[string(tameBytes)] = totalTameDistance
	}
	kl.distanceOfTameFromOrigin = kl.b + totalTameDistance
	return kl
}

func (kl *kangarooLambda) catchKangaroos(targetX, targetY *big.Int) (uint64, bool) {
	var z uint64
	var wildX, wildY *big.Int
	for {
		if z == 0 {
			wildX = targetX
			wildY = targetY
		} else {
			x, y := sm2.P256().ScalarBaseMult(big.NewInt(int64(z)).Bytes())
			wildX, wildY = sm2.P256().Add(targetX, targetY, x, y)
		}
		totalWildDistance := uint64(0)

		// maxNumberOfJumpsForWild := int(float64(b)/alpha) + tameKangarooJumps
		for i := uint64(0); i < kl.tameKangarooJumps; i++ {
			v := new(big.Int).Mod(wildX, big.NewInt(int64(kl.d)))
			v.Add(v, big.NewInt(1))
			v.Exp(big.NewInt(2), v, sm2.P256().Params().N)
			x, y := sm2.P256().ScalarBaseMult(v.Bytes())
			wildX, wildY = sm2.P256().Add(wildX, wildY, x, y)
			totalWildDistance += v.Uint64()
			wildBytes := elliptic.MarshalCompressed(sm2.P256(), wildX, wildY)
			dist, prs := kl.tameKangarooHistory[string(wildBytes)]
			if prs {
				fmt.Println("COLLIEDED WITH TAME")
				computed := dist + kl.b - totalWildDistance - z
				fmt.Printf("Tame distance: %x, Wild distance: %x, z: %x \n", dist, totalWildDistance, z)
				return computed, true
			}
			if totalWildDistance > kl.distanceOfTameFromOrigin {
				fmt.Println("passed tame kangaroo")
				return 0, false
			}
		}
		z = uint64(rand.Intn(int(kl.b)))
	}
}

func TestKangarooLambdaUint32(t *testing.T) {
	target := uint32(0xffff3fff)
	kl := NewKangarooLambda(1 << 32)
	fmt.Printf("alpha: %v, d: %d, # of jumps for tame: %d\n", kl.alpha, kl.d, kl.tameKangarooJumps)
	targetX, targetY := sm2.P256().ScalarBaseMult(big.NewInt(int64(target)).Bytes())
	computed, found := kl.catchKangaroos(targetX, targetY)
	if !found {
		t.Errorf("Can't resolve the target")
	}
	if uint32(computed) != target {
		t.Errorf("computed <> target")
	}
}
